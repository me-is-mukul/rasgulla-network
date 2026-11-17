// This file can be used for any JavaScript functionality
// For example, handling form submissions, showing progress bars, etc.

// Example: Show a progress bar for file uploads
document.addEventListener('DOMContentLoaded', function() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const fileSize = (file.size / 1024 / 1024).toFixed(2);
                console.log(`File size: ${fileSize} MB`);
            }
        });
    });
});