// Documentation Theme JavaScript
document.addEventListener('DOMContentLoaded', function() {
  // Mobile menu toggle
  const sidebar = document.querySelector('.sidebar');
  const menuToggle = document.querySelector('.menu-toggle');
  
  if (menuToggle) {
    menuToggle.addEventListener('click', function() {
      sidebar.classList.toggle('mobile-open');
    });
  }
  
  // Active link highlighting
  updateActiveLink();
  
  // Search functionality
  setupSearch();
  
  // Table of contents generation
  generateTableOfContents();
  
  // Smooth scrolling for anchor links
  setupSmoothScrolling();
});

// Update active navigation link
function updateActiveLink() {
  const currentPath = window.location.pathname;
  const navLinks = document.querySelectorAll('.nav-links a');
  
  navLinks.forEach(link => {
    link.classList.remove('active');
    if (link.getAttribute('href') === currentPath) {
      link.classList.add('active');
    }
  });
}

// Simple search functionality
function setupSearch() {
  const searchInput = document.querySelector('.search-box input');
  if (!searchInput) return;
  
  let searchTimeout;
  
  searchInput.addEventListener('input', function() {
    clearTimeout(searchTimeout);
    const query = this.value.toLowerCase();
    
    searchTimeout = setTimeout(() => {
      performSearch(query);
    }, 300);
  });
}

function performSearch(query) {
  if (query.length < 2) {
    showAllItems();
    return;
  }
  
  const navItems = document.querySelectorAll('.nav-links a');
  
  navItems.forEach(item => {
    const text = item.textContent.toLowerCase();
    if (text.includes(query)) {
      item.style.display = 'block';
      item.parentElement.style.display = 'block';
    } else {
      item.style.display = 'none';
      item.parentElement.style.display = 'none';
    }
  });
}

function showAllItems() {
  const navItems = document.querySelectorAll('.nav-links a, .nav-links li');
  navItems.forEach(item => {
    item.style.display = 'block';
  });
}

// Generate table of contents from headings
function generateTableOfContents() {
  const content = document.querySelector('.article');
  if (!content) return;
  
  const headings = content.querySelectorAll('h2, h3, h4');
  if (headings.length === 0) return;
  
  const toc = document.createElement('div');
  toc.className = 'table-of-contents';
  toc.innerHTML = '<h3>Table of Contents</h3><ul></ul>';
  
  const tocList = toc.querySelector('ul');
  
  headings.forEach(heading => {
    // Create anchor link
    const id = generateId(heading.textContent);
    heading.id = id;
    
    const listItem = document.createElement('li');
    listItem.className = `toc-${heading.tagName.toLowerCase()}`;
    
    const link = document.createElement('a');
    link.href = `#${id}`;
    link.textContent = heading.textContent;
    
    listItem.appendChild(link);
    tocList.appendChild(listItem);
  });
  
  // Insert TOC after the first heading
  const firstHeading = content.querySelector('h1, h2');
  if (firstHeading) {
    firstHeading.insertAdjacentElement('afterend', toc);
  } else {
    content.insertBefore(toc, content.firstChild);
  }
}

// Generate URL-friendly ID from text
function generateId(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '') // Remove special characters
    .replace(/\s+/g, '-') // Replace spaces with hyphens
    .replace(/-+/g, '-') // Remove multiple hyphens
    .trim('-'); // Remove leading/trailing hyphens
}

// Setup smooth scrolling for anchor links
function setupSmoothScrolling() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      e.preventDefault();
      
      const targetId = this.getAttribute('href');
      const targetElement = document.querySelector(targetId);
      
      if (targetElement) {
        targetElement.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });
}

// Copy to clipboard functionality for code blocks
function setupCodeBlockCopy() {
  document.querySelectorAll('pre').forEach(pre => {
    const code = pre.querySelector('code');
    if (!code) return;
    
    const copyButton = document.createElement('button');
    copyButton.className = 'copy-button';
    copyButton.textContent = 'Copy';
    copyButton.title = 'Copy to clipboard';
    
    copyButton.addEventListener('click', function() {
      navigator.clipboard.writeText(code.textContent).then(() => {
        copyButton.textContent = 'Copied!';
        setTimeout(() => {
          copyButton.textContent = 'Copy';
        }, 2000);
      });
    });
    
    pre.style.position = 'relative';
    pre.appendChild(copyButton);
  });
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', setupCodeBlockCopy);

// Dark mode toggle (if needed)
function toggleDarkMode() {
  document.body.classList.toggle('dark-mode');
  const isDarkMode = document.body.classList.contains('dark-mode');
  localStorage.setItem('darkMode', isDarkMode);
  
  // Update icon if there's a button
  const darkModeButton = document.querySelector('.dark-mode-toggle');
  if (darkModeButton) {
    darkModeButton.innerHTML = isDarkMode ? '☀️' : '🌙';
  }
}

// Check for saved dark mode preference
if (localStorage.getItem('darkMode') === 'true') {
  document.body.classList.add('dark-mode');
}