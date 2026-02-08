.PHONY: all build convert clean update-submodule help

# Default target
all: build convert

# Build the converter
build:
	go build -o bin/convert ./cmd/convert

# Run conversion
convert: build
	./bin/convert -upstream upstream -output output

# Clean generated files
clean:
	rm -rf bin/ output/*.yml

# Update submodule to latest
update-submodule:
	git submodule update --remote upstream

# Update submodule and regenerate
update: update-submodule convert

# Show help
help:
	@echo "Available targets:"
	@echo "  all              - Build converter and run conversion (default)"
	@echo "  build            - Build the converter binary"
	@echo "  convert          - Run conversion (builds first if needed)"
	@echo "  clean            - Remove built binaries and generated YAML"
	@echo "  update-submodule - Update upstream submodule to latest commit"
	@echo "  update           - Update submodule and regenerate YAML"
	@echo "  help             - Show this help message"
