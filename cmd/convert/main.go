package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Query struct {
	Name        string
	Description string
	Query       string
	Platform    string
	Tags        []string
	Interval    int    // execution interval in seconds (0 = not specified)
	Level       int    // 1, 2, 3 for detection queries; 0 for others
	Category    string // detection, policy, incident_response
	Subcategory string // e.g., execution, persistence, c2
}

var (
	tagsRegex     = regexp.MustCompile(`^--\s*tags:\s*(.+)$`)
	platformRegex = regexp.MustCompile(`^--\s*platform:\s*(.+)$`)
	intervalRegex = regexp.MustCompile(`^--\s*interval:\s*(\d+)$`)
	levelRegex    = regexp.MustCompile(`^(\d)-(.+)\.sql$`)
)

func main() {
	upstreamDir := flag.String("upstream", "upstream", "Path to osquery-defense-kit submodule")
	outputDir := flag.String("output", "output", "Output directory for FleetDM YAML files")
	flag.Parse()

	queries, err := parseAllQueries(*upstreamDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing queries: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsed %d queries\n", len(queries))

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	if err := writeFleetYAML(queries, *outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing YAML: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully generated FleetDM YAML files")
}

func parseAllQueries(upstreamDir string) ([]Query, error) {
	var queries []Query

	categories := []string{"detection", "policy", "incident_response"}

	for _, category := range categories {
		catPath := filepath.Join(upstreamDir, category)
		if _, err := os.Stat(catPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.WalkDir(catPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".sql") {
				return nil
			}

			query, err := parseQuery(path, category, catPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", path, err)
				return nil
			}

			queries = append(queries, query)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking %s: %w", category, err)
		}
	}

	return queries, nil
}

func parseQuery(path, category, categoryPath string) (Query, error) {
	file, err := os.Open(path)
	if err != nil {
		return Query{}, err
	}
	defer file.Close()

	var q Query
	q.Category = category

	// Extract subcategory from path (e.g., detection/execution/file.sql -> execution)
	relPath, _ := filepath.Rel(categoryPath, path)
	parts := strings.Split(relPath, string(os.PathSeparator))
	if len(parts) > 1 {
		q.Subcategory = parts[0]
	}

	// Extract level and base name from filename
	filename := filepath.Base(path)
	if matches := levelRegex.FindStringSubmatch(filename); matches != nil {
		fmt.Sscanf(matches[1], "%d", &q.Level)
		filename = matches[2] + ".sql"
	}

	// Generate human-readable name
	q.Name = generateName(filename, q.Category, q.Subcategory)

	scanner := bufio.NewScanner(file)
	var sqlLines []string
	firstComment := true
	inHeader := true

	for scanner.Scan() {
		line := scanner.Text()

		if inHeader && strings.HasPrefix(line, "--") {
			commentContent := strings.TrimPrefix(line, "--")
			commentContent = strings.TrimSpace(commentContent)

			// Check for tags
			if matches := tagsRegex.FindStringSubmatch(line); matches != nil {
				q.Tags = strings.Fields(matches[1])
				continue
			}

			// Check for platform
			if matches := platformRegex.FindStringSubmatch(line); matches != nil {
				q.Platform = normalizePlatform(strings.TrimSpace(matches[1]))
				continue
			}

			// Check for interval
			if matches := intervalRegex.FindStringSubmatch(line); matches != nil {
				fmt.Sscanf(matches[1], "%d", &q.Interval)
				continue
			}

			// First non-empty comment line is the description
			if firstComment && commentContent != "" && !strings.HasPrefix(commentContent, "references:") && !strings.HasPrefix(commentContent, "false positives:") {
				q.Description = commentContent
				firstComment = false
			}
		} else if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "--") {
			inHeader = false
		}

		// Collect SQL (including comments within SQL)
		if !inHeader || !strings.HasPrefix(line, "--") {
			sqlLines = append(sqlLines, line)
		}
	}

	// Trim leading empty lines from SQL
	for len(sqlLines) > 0 && strings.TrimSpace(sqlLines[0]) == "" {
		sqlLines = sqlLines[1:]
	}

	q.Query = strings.TrimSpace(strings.Join(sqlLines, "\n"))

	if q.Description == "" {
		q.Description = q.Name
	}

	return q, scanner.Err()
}

func generateName(filename, category, subcategory string) string {
	// Remove .sql extension
	name := strings.TrimSuffix(filename, ".sql")

	// Replace hyphens and underscores with spaces
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.ReplaceAll(name, "_", " ")

	// Title case
	name = strings.Title(name)

	// Add category prefix for clarity
	if subcategory != "" {
		return fmt.Sprintf("[%s/%s] %s", category, subcategory, name)
	}
	return fmt.Sprintf("[%s] %s", category, name)
}

func normalizePlatform(platform string) string {
	switch strings.ToLower(platform) {
	case "darwin", "macos":
		return "darwin"
	case "linux":
		return "linux"
	case "posix":
		return "darwin,linux"
	case "windows":
		return "windows"
	default:
		return ""
	}
}

func writeFleetYAML(queries []Query, outputDir string) error {
	// Group by category
	groups := map[string][]Query{
		"detection":         {},
		"policy":            {},
		"incident_response": {},
	}

	for _, q := range queries {
		groups[q.Category] = append(groups[q.Category], q)
	}

	for category, categoryQueries := range groups {
		if len(categoryQueries) == 0 {
			continue
		}

		filename := filepath.Join(outputDir, fmt.Sprintf("chainguard-%s.yml", strings.ReplaceAll(category, "_", "-")))
		file, err := os.Create(filename)
		if err != nil {
			return fmt.Errorf("creating %s: %w", filename, err)
		}

		for i, q := range categoryQueries {
			if i > 0 {
				file.WriteString("---\n")
			}
			if err := writeQueryYAML(file, q, 0); err != nil {
				file.Close()
				return err
			}
		}
		file.Close()
		fmt.Printf("Wrote %s (%d queries)\n", filename, len(categoryQueries))
	}

	// Write detection rules with 5-minute interval for all
	if detectionQueries := groups["detection"]; len(detectionQueries) > 0 {
		scheduledFile := filepath.Join(outputDir, "chainguard-detection-5min.yml")
		file, err := os.Create(scheduledFile)
		if err != nil {
			return fmt.Errorf("creating %s: %w", scheduledFile, err)
		}

		for i, q := range detectionQueries {
			if i > 0 {
				file.WriteString("---\n")
			}
			if err := writeQueryYAML(file, q, 300); err != nil {
				file.Close()
				return err
			}
		}
		file.Close()
		fmt.Printf("Wrote %s (%d queries, 5-min interval)\n", scheduledFile, len(detectionQueries))
	}

	// Also write a combined file
	combinedFile := filepath.Join(outputDir, "chainguard-all.yml")
	file, err := os.Create(combinedFile)
	if err != nil {
		return fmt.Errorf("creating combined file: %w", err)
	}
	defer file.Close()

	for i, q := range queries {
		if i > 0 {
			file.WriteString("---\n")
		}
		if err := writeQueryYAML(file, q, 0); err != nil {
			return err
		}
	}
	fmt.Printf("Wrote %s (%d queries)\n", combinedFile, len(queries))

	return nil
}

func writeQueryYAML(w *os.File, q Query, intervalOverride int) error {
	// Escape description for YAML
	desc := escapeYAML(q.Description)
	query := escapeYAMLMultiline(q.Query)

	w.WriteString("apiVersion: v1\n")
	w.WriteString("kind: query\n")
	w.WriteString("spec:\n")
	w.WriteString(fmt.Sprintf("  name: %s\n", escapeYAML(q.Name)))
	w.WriteString(fmt.Sprintf("  description: %s\n", desc))

	// Use literal block scalar for multi-line queries
	w.WriteString("  query: |\n")
	for _, line := range strings.Split(query, "\n") {
		w.WriteString(fmt.Sprintf("    %s\n", line))
	}

	if q.Platform != "" {
		w.WriteString(fmt.Sprintf("  platform: %s\n", q.Platform))
	}

	// Add interval: use override if specified, otherwise use query's interval
	interval := q.Interval
	if intervalOverride > 0 {
		interval = intervalOverride
	}
	if interval > 0 {
		w.WriteString(fmt.Sprintf("  interval: %d\n", interval))
	}

	// Add logging type based on category
	if q.Category == "detection" || q.Category == "policy" {
		w.WriteString("  logging: differential\n")
	} else {
		w.WriteString("  logging: snapshot\n")
	}

	return nil
}

func escapeYAML(s string) string {
	// If string contains special characters, quote it
	if strings.ContainsAny(s, ":#{}[]|>&*!?'\"\\") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "@") {
		// Use double quotes and escape internal quotes
		s = strings.ReplaceAll(s, "\\", "\\\\")
		s = strings.ReplaceAll(s, "\"", "\\\"")
		return fmt.Sprintf("\"%s\"", s)
	}
	return s
}

func escapeYAMLMultiline(s string) string {
	// For multiline content in literal block scalar, we don't need to escape
	return s
}
