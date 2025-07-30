#!/usr/bin/env pwsh
# Advanced TUI Demo Script - Recon Platform
# This script demonstrates all the advanced TUI features

Write-Host "🎯 Recon Platform - Advanced TUI Demo" -ForegroundColor Blue
Write-Host "======================================" -ForegroundColor Blue
Write-Host ""

Write-Host "✨ Features to Demonstrate:" -ForegroundColor Green
Write-Host "  • Interactive Target Selection with Claude UI styling" -ForegroundColor White
Write-Host "  • Real-time Scan Progress with animated spinners" -ForegroundColor White
Write-Host "  • Results Visualization with color-coded severity" -ForegroundColor White
Write-Host "  • Responsive design and keyboard navigation" -ForegroundColor White
Write-Host ""

Write-Host "🎮 Demo Instructions:" -ForegroundColor Yellow
Write-Host "1. Target Selection View:" -ForegroundColor White
Write-Host "   - Enter a target (e.g., example.com or 192.168.1.0/24)" -ForegroundColor Gray
Write-Host "   - Use Tab to switch to scan type selection" -ForegroundColor Gray
Write-Host "   - Use ↑↓ arrows to choose scan type" -ForegroundColor Gray
Write-Host "   - Press ? to see help overlay" -ForegroundColor Gray
Write-Host "   - Press Enter to start scan" -ForegroundColor Gray
Write-Host ""

Write-Host "2. Scan Progress View:" -ForegroundColor White
Write-Host "   - Watch 6 scanning phases with progress bars" -ForegroundColor Gray
Write-Host "   - See live results counter update" -ForegroundColor Gray
Write-Host "   - Press S to skip to results (for demo)" -ForegroundColor Gray
Write-Host ""

Write-Host "3. Results View:" -ForegroundColor White
Write-Host "   - Navigate results with ↑↓ arrows" -ForegroundColor Gray
Write-Host "   - See color-coded severity (🔴 High, 🟡 Medium, 🔵 Info)" -ForegroundColor Gray
Write-Host "   - Press R to start new scan" -ForegroundColor Gray
Write-Host "   - Press Q to quit" -ForegroundColor Gray
Write-Host ""

Write-Host "🚀 Starting Interactive Demo..." -ForegroundColor Green
Write-Host "Press Ctrl+C in the TUI to return to this script" -ForegroundColor Yellow
Write-Host ""

# Start the interactive TUI
& ".\recon.exe" scan --interactive

Write-Host ""
Write-Host "🎉 Demo Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 TUI Features Summary:" -ForegroundColor Blue
Write-Host "✅ Modern Claude UI inspired design" -ForegroundColor Green
Write-Host "✅ Interactive target selection with validation" -ForegroundColor Green
Write-Host "✅ Real-time scan progress with 6 phases" -ForegroundColor Green
Write-Host "✅ Animated spinners and progress bars" -ForegroundColor Green
Write-Host "✅ Color-coded results visualization" -ForegroundColor Green
Write-Host "✅ Full keyboard navigation" -ForegroundColor Green
Write-Host "✅ Responsive terminal layout" -ForegroundColor Green
Write-Host "✅ Professional styling and colors" -ForegroundColor Green
Write-Host ""

Write-Host "🔧 Next Steps for Production:" -ForegroundColor Yellow
Write-Host "1. Connect to real scanning pipeline" -ForegroundColor White
Write-Host "2. Integrate with database for result persistence" -ForegroundColor White
Write-Host "3. Add tool integration (Nuclei, Nmap, Subfinder)" -ForegroundColor White
Write-Host "4. Implement export functionality" -ForegroundColor White
Write-Host "5. Add configuration and settings panel" -ForegroundColor White
Write-Host ""

Write-Host "🎨 Design Achievement:" -ForegroundColor Magenta
Write-Host "Created a professional-grade TUI that rivals commercial tools" -ForegroundColor White
Write-Host "with modern styling inspired by Claude UI and Gemini CLI!" -ForegroundColor White
