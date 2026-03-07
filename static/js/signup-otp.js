// ============================================
// EMAIL OTP FUNCTIONALITY FOR SIGNUP
// ============================================

let emailInterval = null;

// Timer function
function startOTPTimer(elementId, durationSeconds) {
    let timeRemaining = durationSeconds;
    const timerElement = document.getElementById(elementId);
    
    // Update initial display
    timerElement.style.color = '#00f5ff';
    timerElement.textContent = `(${timeRemaining}s)`;
    
    // Start countdown
    const interval = setInterval(() => {
        timeRemaining--;
        timerElement.textContent = `(${timeRemaining}s)`;
        
        // Change color when time is running out
        if (timeRemaining <= 30) {
            timerElement.style.color = '#f59e0b'; // Orange
        }
        
        if (timeRemaining <= 10) {
            timerElement.style.color = '#ef4444'; // Red
        }
        
        // Timer expired
        if (timeRemaining <= 0) {
            clearInterval(interval);
            timerElement.textContent = '(Expired ❌)';
            timerElement.style.color = '#ef4444';
        }
    }, 1000);
    
    return interval;
}

// Send Email OTP
document.getElementById("sendEmailOTP").addEventListener('click', function() {
    const emailInput = document.getElementById("email");
    const email = emailInput.value.trim();
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        alert("❌ Please enter a valid email address first!");
        emailInput.focus();
        return;
    }
    
    // Disable button and show loading
    this.disabled = true;
    this.textContent = 'Sending...';
    
    // Send OTP request
    fetch("/api/send_email_otp", {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: email})
    })
    .then(response => response.json())
    .then(data => {
        if (data.sent) {
            // Show OTP input field
            document.getElementById("emailOtpWrap").style.display = "block";
            
            // Clear previous timer if exists
            if (emailInterval) {
                clearInterval(emailInterval);
            }
            
            // Start new 2-minute timer
            emailInterval = startOTPTimer("emailTimer", 120);
            
            // Clear status
            document.getElementById("emailOtpStatus").textContent = '';
            
            // Update button
            this.textContent = 'Resend OTP';
            this.disabled = false;
            
            // Show success message
            alert('✅ OTP sent to your email! Please check your inbox.');
            
            // Focus on OTP input
            document.getElementById("emailOTP").focus();
        } else {
            alert('❌ Failed to send OTP: ' + (data.error || 'Unknown error'));
            this.textContent = 'Send OTP';
            this.disabled = false;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('❌ Network error: ' + error.message);
        this.textContent = 'Send OTP';
        this.disabled = false;
    });
});

// Verify Email OTP (auto-verify when 6 digits entered)
document.getElementById("emailOTP").addEventListener('input', function() {
    const otp = this.value.trim();
    
    // Only allow numbers
    this.value = this.value.replace(/[^0-9]/g, '');
    
    // Auto-verify when 6 digits entered
    if (otp.length === 6) {
        fetch("/api/verify_email_otp", {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({otp: otp})
        })
        .then(response => response.json())
        .then(data => {
            const statusElement = document.getElementById('emailOtpStatus');
            
            if (data.valid) {
                // OTP is correct
                statusElement.textContent = '✅';
                
                // Update validations object (defined in signup.html)
                if (typeof validations !== 'undefined') {
                    validations.emailOtp = true;
                    checkFormValidity();
                }
                
                // Stop timer
                if (emailInterval) {
                    clearInterval(emailInterval);
                }
                
                // Update timer display
                const timerElement = document.getElementById('emailTimer');
                timerElement.textContent = '(Verified ✅)';
                timerElement.style.color = '#10b981';
                
                // Disable OTP input
                this.disabled = true;
                this.style.opacity = '0.6';
                
            } else {
                // OTP is incorrect
                statusElement.textContent = '❌';
                
                if (typeof validations !== 'undefined') {
                    validations.emailOtp = false;
                    checkFormValidity();
                }
            }
        })
        .catch(error => {
            console.error('Verification error:', error);
            document.getElementById('emailOtpStatus').textContent = '❌';
        });
    } else {
        // Clear status if less than 6 digits
        document.getElementById('emailOtpStatus').textContent = '';
        
        if (typeof validations !== 'undefined') {
            validations.emailOtp = false;
            checkFormValidity();
        }
    }
});

// Clear OTP status when input is cleared
document.getElementById("emailOTP").addEventListener('focus', function() {
    if (this.value.length === 0) {
        document.getElementById('emailOtpStatus').textContent = '';
    }
});
