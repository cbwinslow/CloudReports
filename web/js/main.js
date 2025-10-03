// Web Interface JavaScript for Enterprise Reporting System
class ReportDashboard {
    constructor() {
        this.currentView = 'dashboard';
        this.charts = {};
        this.apiEndpoint = '/api/v1'; // This would be configured based on your API setup
        
        this.init();
    }
    
    init() {
        this.setupNavigation();
        this.setupEventListeners();
        this.loadDashboardData();
        this.initializeCharts();
    }
    
    setupNavigation() {
        const navLinks = document.querySelectorAll('.nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const view = link.getAttribute('data-view');
                this.switchView(view);
            });
        });
    }
    
    setupEventListeners() {
        // Refresh reports button
        const refreshBtn = document.getElementById('refresh-reports');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadReportsData();
            });
        }
        
        // Filter controls
        const typeFilter = document.getElementById('report-type-filter');
        const timeFilter = document.getElementById('time-range-filter');
        
        if (typeFilter) {
            typeFilter.addEventListener('change', () => {
                this.loadReportsData();
            });
        }
        
        if (timeFilter) {
            timeFilter.addEventListener('change', () => {
                this.loadReportsData();
            });
        }
    }
    
    switchView(view) {
        // Hide all views
        document.querySelectorAll('.view').forEach(viewEl => {
            viewEl.classList.remove('active');
        });
        
        // Show selected view
        document.getElementById(`${view}-view`).classList.add('active');
        
        // Update active nav link
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        
        document.querySelector(`[data-view="${view}"]`).classList.add('active');
        
        // Update page title
        document.getElementById('page-title').textContent = 
            view.charAt(0).toUpperCase() + view.slice(1);
        
        // Load view-specific data
        this.loadViewData(view);
        
        this.currentView = view;
    }
    
    loadViewData(view) {
        switch(view) {
            case 'dashboard':
                this.loadDashboardData();
                break;
            case 'reports':
                this.loadReportsData();
                break;
            case 'systems':
                this.loadSystemsData();
                break;
            case 'network':
                this.loadNetworkData();
                break;
            case 'filesystem':
                this.loadFilesystemData();
                break;
            case 'security':
                this.loadSecurityData();
                break;
        }
    }
    
    async loadDashboardData() {
        try {
            // Simulate API calls with mock data
            // In real implementation, you'd fetch from /api/v1 endpoints
            
            // Update summary cards
            document.getElementById('total-systems').textContent = '12';
            document.getElementById('total-reports').textContent = '145';
            document.getElementById('total-alerts').textContent = '3';
            document.getElementById('success-rate').textContent = '97.8%';
            
            // Load recent reports
            this.loadRecentReports();
            
            // Update charts with new data
            setTimeout(() => {
                this.updatePerformanceChart();
                this.updateStatusChart();
                this.updateSystemTypesChart();
            }, 500);
            
        } catch (error) {
            console.error('Error loading dashboard data:', error);
            this.showError('Failed to load dashboard data');
        }
    }
    
    loadRecentReports() {
        const reportsContainer = document.getElementById('recent-reports');
        const mockReports = [
            { id: 1, hostname: 'server1', type: 'system', timestamp: '2023-01-01T10:00:00Z', status: 'success' },
            { id: 2, hostname: 'server2', type: 'network', timestamp: '2023-01-01T09:45:00Z', status: 'success' },
            { id: 3, hostname: 'server3', type: 'filesystem', timestamp: '2023-01-01T09:30:00Z', status: 'success' },
            { id: 4, hostname: 'server1', type: 'error', timestamp: '2023-01-01T09:15:00Z', status: 'warning' },
            { id: 5, hostname: 'server4', type: 'system', timestamp: '2023-01-01T09:00:00Z', status: 'success' }
        ];
        
        reportsContainer.innerHTML = '';
        
        mockReports.forEach(report => {
            const reportEl = document.createElement('div');
            reportEl.className = `report-item ${report.type}`;
            
            const time = new Date(report.timestamp).toLocaleString();
            
            reportEl.innerHTML = `
                <div>
                    <h4>${report.hostname}</h4>
                    <p>Type: ${report.type} | ${time}</p>
                </div>
                <div>
                    <span class="status-indicator status-${report.status}"></span>
                </div>
            `;
            
            reportsContainer.appendChild(reportEl);
        });
    }
    
    async loadReportsData() {
        try {
            // Get filter values
            const typeFilter = document.getElementById('report-type-filter').value;
            const timeFilter = document.getElementById('time-range-filter').value;
            
            // In real implementation, fetch from API
            // const response = await fetch(`${this.apiEndpoint}/reports?type=${typeFilter}&timeRange=${timeFilter}`);
            // const reports = await response.json();
            
            // Mock data for demo
            const mockReports = [
                { id: 1, hostname: 'server1', type: 'system', timestamp: '2023-01-01T10:00:00Z', summary: { cpu: '15%', memory: '42%', disk: '78%' } },
                { id: 2, hostname: 'server2', type: 'network', timestamp: '2023-01-01T09:45:00Z', summary: { connections: '42', bandwidth: '1.2GB' } },
                { id: 3, hostname: 'server3', type: 'filesystem', timestamp: '2023-01-01T09:30:00Z', summary: { root_usage: '85%', home_usage: '45%' } },
                { id: 4, hostname: 'server1', type: 'error', timestamp: '2023-01-01T09:15:00Z', summary: { errors: '3 critical', warnings: '7' } },
                { id: 5, hostname: 'server4', type: 'container', timestamp: '2023-01-01T09:00:00Z', summary: { running: 12, stopped: 2 } }
            ];
            
            const reportsGrid = document.getElementById('reports-grid');
            reportsGrid.innerHTML = '';
            
            mockReports.forEach(report => {
                const reportCard = document.createElement('div');
                reportCard.className = 'report-card';
                
                const time = new Date(report.timestamp).toLocaleString();
                
                reportCard.innerHTML = `
                    <h3>${report.hostname}</h3>
                    <span class="report-type ${report.type}">${report.type}</span>
                    <div class="report-summary">
                        ${Object.entries(report.summary).map(([key, value]) => 
                            `<div class="metric"><span>${key.replace('_', ' ')}:</span><span class="metric-value">${value}</span></div>`
                        ).join('')}
                    </div>
                    <div class="report-meta">
                        <span>${time}</span>
                        <span>ID: ${report.id}</span>
                    </div>
                `;
                
                reportsGrid.appendChild(reportCard);
            });
            
        } catch (error) {
            console.error('Error loading reports:', error);
            this.showError('Failed to load reports');
        }
    }
    
    async loadSystemsData() {
        try {
            // In real implementation, fetch from API
            // const response = await fetch(`${this.apiEndpoint}/systems`);
            // const systems = await response.json();
            
            // Mock data for demo
            const mockSystems = [
                { id: 1, name: 'server1', status: 'active', type: 'physical', 
                  metrics: { cpu: '15%', memory: '42%', disk: '78%' } },
                { id: 2, name: 'server2', status: 'active', type: 'virtual', 
                  metrics: { cpu: '87%', memory: '89%', disk: '92%' } },
                { id: 3, name: 'server3', status: 'warning', type: 'physical', 
                  metrics: { cpu: '95%', memory: '76%', disk: '65%' } },
                { id: 4, name: 'server4', status: 'active', type: 'virtual', 
                  metrics: { cpu: '23%', memory: '34%', disk: '45%' } }
            ];
            
            const systemsGrid = document.getElementById('systems-grid');
            systemsGrid.innerHTML = '';
            
            mockSystems.forEach(system => {
                const systemCard = document.createElement('div');
                systemCard.className = 'system-card';
                
                systemCard.innerHTML = `
                    <h3>
                        <span class="status-indicator status-${system.status}"></span>
                        ${system.name}
                    </h3>
                    <div class="system-type">${system.type}</div>
                    <div class="system-metrics">
                        ${Object.entries(system.metrics).map(([key, value]) => 
                            `<div class="metric"><span>${key.toUpperCase()}:</span><span class="metric-value">${value}</span></div>`
                        ).join('')}
                    </div>
                `;
                
                systemsGrid.appendChild(systemCard);
            });
            
        } catch (error) {
            console.error('Error loading systems:', error);
            this.showError('Failed to load systems data');
        }
    }
    
    initializeCharts() {
        // Initialize charts with empty data
        const perfCtx = document.getElementById('performanceChart').getContext('2d');
        this.charts.performance = new Chart(perfCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'CPU %', data: [], borderColor: '#3b82f6', tension: 0.1 },
                    { label: 'Memory %', data: [], borderColor: '#10b981', tension: 0.1 },
                    { label: 'Disk %', data: [], borderColor: '#f59e0b', tension: 0.1 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
        
        const statusCtx = document.getElementById('statusChart').getContext('2d');
        this.charts.status = new Chart(statusCtx, {
            type: 'doughnut',
            data: {
                labels: ['Success', 'Failed', 'Pending'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#10b981', '#ef4444', '#f59e0b']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
        
        const typesCtx = document.getElementById('systemTypesChart').getContext('2d');
        this.charts.types = new Chart(typesCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'System Count',
                    data: [],
                    backgroundColor: '#2563eb'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    updatePerformanceChart() {
        if (this.charts.performance) {
            // Generate mock data
            const now = new Date();
            const labels = [];
            const cpuData = [];
            const memoryData = [];
            const diskData = [];
            
            for (let i = 9; i >= 0; i--) {
                const time = new Date(now.getTime() - i * 60000);
                labels.push(time.toLocaleTimeString());
                cpuData.push(Math.random() * 100);
                memoryData.push(Math.random() * 100);
                diskData.push(Math.random() * 100);
            }
            
            this.charts.performance.data.labels = labels;
            this.charts.performance.data.datasets[0].data = cpuData;
            this.charts.performance.data.datasets[1].data = memoryData;
            this.charts.performance.data.datasets[2].data = diskData;
            this.charts.performance.update();
        }
    }
    
    updateStatusChart() {
        if (this.charts.status) {
            this.charts.status.data.datasets[0].data = [130, 3, 12]; // success, failed, pending
            this.charts.status.update();
        }
    }
    
    updateSystemTypesChart() {
        if (this.charts.types) {
            this.charts.types.data.labels = ['Physical', 'Virtual', 'Container'];
            this.charts.types.data.datasets[0].data = [8, 4, 0];
            this.charts.types.update();
        }
    }
    
    async loadNetworkData() {
        // Implementation for network-specific data
        console.log('Loading network data...');
        this.showMessage('Network view loaded (demo implementation)');
    }
    
    async loadFilesystemData() {
        // Implementation for filesystem-specific data
        console.log('Loading filesystem data...');
        this.showMessage('Filesystem view loaded (demo implementation)');
    }
    
    async loadSecurityData() {
        // Implementation for security-specific data
        console.log('Loading security data...');
        this.showMessage('Security view loaded (demo implementation)');
    }
    
    showMessage(message) {
        // Create temporary alert message
        const alertEl = document.createElement('div');
        alertEl.className = 'alert alert-info';
        alertEl.innerHTML = `<i class="fas fa-info-circle"></i> ${message}`;
        
        const mainContent = document.querySelector('.main-content');
        mainContent.insertBefore(alertEl, mainContent.firstChild);
        
        // Remove after 3 seconds
        setTimeout(() => {
            if (alertEl.parentNode) {
                alertEl.parentNode.removeChild(alertEl);
            }
        }, 3000);
    }
    
    showError(message) {
        // Create temporary error message
        const alertEl = document.createElement('div');
        alertEl.className = 'alert alert-error';
        alertEl.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${message}`;
        
        const mainContent = document.querySelector('.main-content');
        mainContent.insertBefore(alertEl, mainContent.firstChild);
        
        // Remove after 5 seconds
        setTimeout(() => {
            if (alertEl.parentNode) {
                alertEl.parentNode.removeChild(alertEl);
            }
        }, 5000);
    }
    
    // Mock API functions for demonstration
    async mockApiCall(endpoint) {
        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Return mock data based on endpoint
        switch(endpoint) {
            case '/reports':
                return { 
                    data: [
                        { id: 1, hostname: 'server1', type: 'system', timestamp: new Date().toISOString() }
                    ],
                    pagination: { page: 1, total: 1 }
                };
            case '/systems':
                return { 
                    data: [
                        { id: 1, name: 'server1', status: 'active' }
                    ]
                };
            default:
                return { data: [] };
        }
    }
}

// Initialize the dashboard when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new ReportDashboard();
});

// Additional utility functions
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}