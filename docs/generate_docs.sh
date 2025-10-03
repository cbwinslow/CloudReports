#!/bin/bash

# Documentation Generator for Enterprise Reporting System
# This script converts Markdown documentation to HTML with the professional theme

DOC_DIR="/home/cbwinslow/reports/docs"
THEME_DIR="$DOC_DIR/theme"
HTML_DIR="$DOC_DIR/html"

# Function to convert Markdown to HTML with theme
convert_md_to_html() {
    local md_file="$1"
    local html_file="$2"
    local title="$3"
    
    # Extract the content from the markdown file (without frontmatter)
    CONTENT=$(sed '1,/^---$/d' "$md_file" | markdown || pandoc -f markdown -t html "$md_file")
    
    # Use pandoc if markdown is not available
    if ! command -v markdown >/dev/null 2>&1; then
        CONTENT=$(pandoc -f markdown -t html -o /dev/stdout "$md_file")
    else
        CONTENT=$(markdown "$md_file")
    fi
    
    # Create HTML with theme
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$title - Enterprise Reporting System</title>
    <meta name="description" content="Documentation for the Enterprise Reporting System">
    <link rel="stylesheet" href="theme/css/style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
</head>
<body>
    <div class="layout">
        <nav class="sidebar">
            <div class="sidebar-header">
                <h1>
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                    Enterprise Reporting
                </h1>
            </div>
            
            <div class="docsearch">
                <div class="search-box">
                    <input type="text" placeholder="Search documentation...">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="20" height="20">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                </div>
            </div>
            
            <ul class="nav-links">
                <li><a href="index.html">Overview</a></li>
                <li><a href="architecture.html">Architecture</a></li>
                <li><a href="configuration.html">Configuration</a></li>
                <li><a href="security.html">Security</a></li>
                <li><a href="deployment.html">Deployment</a></li>
                <li><a href="integrations.html">Integrations</a></li>
                <li><a href="api.html">API Reference</a></li>
                <li><a href="compliance.html">Compliance</a></li>
                <li><a href="monitoring.html">Monitoring</a></li>
            </ul>
        </nav>
        
        <main class="main-content">
            <article class="article">
                <h1>$title</h1>
                $CONTENT
            </article>
        </main>
    </div>
    
    <script src="theme/js/scripts.js"></script>
</body>
</html>
EOF
}

# Function to generate all documentation
generate_all_docs() {
    echo "Generating HTML documentation..."
    
    # Create HTML output directory
    mkdir -p "$HTML_DIR"
    
    # Copy theme assets
    cp -r "$THEME_DIR" "$HTML_DIR/"
    
    # Convert each markdown file to HTML
    for md_file in "$DOC_DIR"/*.md; do
        if [ -f "$md_file" ]; then
            filename=$(basename "$md_file" .md)
            html_file="$HTML_DIR/$filename.html"
            title=$(head -n 1 "$md_file" | sed 's/# //')
            
            echo "Converting $md_file to $html_file"
            convert_md_to_html "$md_file" "$html_file" "$title"
        fi
    done
    
    echo "Documentation generation completed!"
}

# Function to build static site
build_static_site() {
    echo "Building static documentation site..."
    
    # Create the output directory
    mkdir -p "$HTML_DIR"
    
    # Generate all documentation
    generate_all_docs
    
    # Create a simple index.html if it doesn't exist
    if [ ! -f "$HTML_DIR/index.html" ]; then
        cat > "$HTML_DIR/index.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Reporting System Documentation</title>
    <link rel="stylesheet" href="theme/css/style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
</head>
<body>
    <div class="layout">
        <nav class="sidebar">
            <div class="sidebar-header">
                <h1>Enterprise Reporting</h1>
            </div>
            <ul class="nav-links">
                <li><a href="index.html" class="active">Documentation Home</a></li>
            </ul>
        </nav>
        
        <main class="main-content">
            <article class="article">
                <h1>Enterprise Reporting System Documentation</h1>
                <p>Select a topic from the navigation menu to view documentation.</p>
            </article>
        </main>
    </div>
</body>
</html>
EOF
    fi
    
    echo "Static site built successfully at $HTML_DIR/"
}

# Parse command line arguments
case "${1:-generate}" in
    "generate")
        generate_all_docs
        ;;
    "build")
        build_static_site
        ;;
    "serve")
        if command -v python3 >/dev/null 2>&1; then
            echo "Serving documentation at http://localhost:8000/docs/html/"
            cd "$HTML_DIR" && python3 -m http.server 8000
        else
            echo "Python3 not found. Install Python3 to serve documentation."
        fi
        ;;
    *)
        echo "Usage: $0 [generate|build|serve]"
        echo "  generate - Convert Markdown docs to HTML"
        echo "  build    - Build complete static site"
        echo "  serve    - Serve documentation locally"
        exit 1
        ;;
esac