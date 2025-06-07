document.addEventListener('DOMContentLoaded', () => {
    // Get DOM elements for password input and feedback display
    const passwordInput = document.getElementById('passwordInput');
    const togglePassword = document.getElementById('togglePassword');
    const suggestPasswordBtn = document.getElementById('suggestPassword');
    const strengthBar = document.getElementById('strengthBar');
    const strengthLabel = document.getElementById('strengthLabel');
    const crackTime = document.getElementById('crackTime');
    const warnings = document.getElementById('warnings');
    const suggestions = document.getElementById('suggestions');

    // Define password validation rules to ensure minimum security requirements
    const validationRules = {
        uppercase: /[A-Z]/,      // Require at least one uppercase letter
        lowercase: /[a-z]/,      // Require at least one lowercase letter
        number: /[0-9]/,         // Require at least one number
        special: /[!@#$%^&*(),.?":{}|<>]/, // Require at least one special character
        minLength: 12            // Minimum length for better security
    };

    // Define visual feedback for different password strength levels
    const strengthConfig = {
        0: { color: 'var(--strength-0)', label: 'Very Weak', width: '20%' },
        1: { color: 'var(--strength-1)', label: 'Weak', width: '40%' },
        2: { color: 'var(--strength-2)', label: 'Moderate', width: '60%' },
        3: { color: 'var(--strength-3)', label: 'Strong', width: '80%' },
        4: { color: 'var(--strength-4)', label: 'Very Strong', width: '100%' }
    };

    // Toggle password visibility between hidden and visible
    togglePassword.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        togglePassword.querySelector('i').classList.toggle('fa-eye');
        togglePassword.querySelector('i').classList.toggle('fa-eye-slash');
    });

    // Check if password is too common or can be cracked quickly
    // This helps prevent dictionary attacks and common password patterns
    function isPasswordTooCommon(password) {
        const result = zxcvbn(password);
        // Consider passwords weak if they score low or can be cracked quickly
        return result.score < 2 || 
               result.crack_times_display.offline_fast_hashing_1e10_per_second.includes('instant') ||
               result.crack_times_display.offline_fast_hashing_1e10_per_second.includes('seconds') ||
               result.crack_times_display.offline_fast_hashing_1e10_per_second.includes('minutes') ||
               result.crack_times_display.offline_fast_hashing_1e10_per_second.includes('hours');
    }

    // Verify if password has sufficient crack time (at least a decade)
    // This ensures passwords are resistant to brute force attacks
    function hasSufficientCrackTime(password) {
        const result = zxcvbn(password);
        const crackTime = result.crack_times_display.offline_fast_hashing_1e10_per_second;
        return crackTime.includes('centuries') || 
               crackTime.includes('decades') || 
               (crackTime.includes('years') && parseInt(crackTime) >= 10);
    }

    // Enhance a moderate password to make it significantly stronger
    // Uses multiple techniques to increase entropy and complexity
    function enhanceModeratePassword(password) {
        // Try multiple variations to find a strong enough password
        // This helps avoid patterns that might be predictable
        for (let attempt = 0; attempt < 5; attempt++) {
            let enhancedPassword = password;
            
            // Define character sets for password enhancement
            const specialChars = '!@#$%^&*';
            const numbers = '0123456789';
            
            // Add three special characters at random positions
            // This increases entropy and makes the password harder to guess
            for (let i = 0; i < 3; i++) {
                const specialChar = specialChars[Math.floor(Math.random() * specialChars.length)];
                const insertPos = Math.floor(Math.random() * (enhancedPassword.length + 1));
                enhancedPassword = enhancedPassword.slice(0, insertPos) + specialChar + enhancedPassword.slice(insertPos);
            }
            
            // Add three numbers at random positions
            // This adds complexity and makes the password more resistant to dictionary attacks
            for (let i = 0; i < 3; i++) {
                const number = numbers[Math.floor(Math.random() * numbers.length)];
                const numInsertPos = Math.floor(Math.random() * (enhancedPassword.length + 1));
                enhancedPassword = enhancedPassword.slice(0, numInsertPos) + number + enhancedPassword.slice(numInsertPos);
            }
            
            // Ensure password starts with uppercase for additional complexity
            if (!validationRules.uppercase.test(enhancedPassword[0])) {
                enhancedPassword = enhancedPassword[0].toUpperCase() + enhancedPassword.slice(1);
            }
            
            // Extend password length to at least 20 characters
            // Longer passwords are exponentially harder to crack
            while (enhancedPassword.length < 20) {
                const randomChar = Math.random().toString(36).slice(-1);
                enhancedPassword += randomChar;
            }

            // Verify this version meets our security requirements
            if (hasSufficientCrackTime(enhancedPassword)) {
                return enhancedPassword;
            }
        }

        // Return null if we couldn't create a strong enough password
        // This prevents suggesting weak variations
        return null;
    }

    // Generate a stronger version of the current password
    // Only suggests improvements for moderate passwords to avoid unnecessary complexity
    function generateSimilarPassword(originalPassword) {
        if (!originalPassword) return '';

        const result = zxcvbn(originalPassword);
        
        // Don't suggest improvements for weak passwords
        // This prevents creating variations of already weak passwords
        if (isPasswordTooCommon(originalPassword)) {
            return null;
        }
        
        // Only enhance moderate passwords
        // Strong passwords don't need enhancement
        if (result.score === 2) {
            const enhancedPassword = enhanceModeratePassword(originalPassword);
            if (enhancedPassword && hasSufficientCrackTime(enhancedPassword)) {
                return enhancedPassword;
            }
            return null;
        }
        
        // Don't suggest changes for already strong passwords
        // This prevents unnecessary complexity
        if (result.score >= 3) {
            return null;
        }

        return null;
    }

    // Handle password suggestion button clicks
    // Provides appropriate feedback based on password strength
    suggestPasswordBtn.addEventListener('click', () => {
        const currentPassword = passwordInput.value;
        if (currentPassword) {
            const suggestedPassword = generateSimilarPassword(currentPassword);
            
            if (suggestedPassword === null) {
                const result = zxcvbn(currentPassword);
                if (result.score < 2) {
                    // Provide guidance for weak passwords
                    warnings.textContent = "This password is too common or weak. Please choose a different base password that's not in common dictionaries.";
                    suggestions.innerHTML = `
                        <li>Avoid common words, names, or patterns</li>
                        <li>Use a unique combination of words that aren't related</li>
                        <li>Consider using a passphrase instead of a single word</li>
                        <li>Mix different languages or add random characters</li>
                    `;
                } else if (result.score >= 3) {
                    // Acknowledge strong passwords
                    warnings.textContent = "Your password is already strong! No suggestions needed.";
                    suggestions.innerHTML = `
                        <li>Keep using this strong password</li>
                        <li>Make sure to use different strong passwords for different accounts</li>
                    `;
                } else {
                    // Guide users when enhancement isn't possible
                    warnings.textContent = "Unable to create a stronger version of this password. Please try a different base password.";
                    suggestions.innerHTML = `
                        <li>Try using a longer base password</li>
                        <li>Use a combination of unrelated words</li>
                        <li>Consider using a passphrase with special characters</li>
                    `;
                }
                return;
            }

            // Update the input with the enhanced password
            passwordInput.value = suggestedPassword;
            updatePasswordStrength(suggestedPassword);
        }
    });

    // Validate password against security requirements
    // Provides specific feedback for weak passwords
    function getValidationFeedback(password) {
        const feedback = [];
        const result = zxcvbn(password);
        
        // Only show basic validation feedback for weak passwords
        // This prevents cluttering the interface for strong passwords
        if (result.score < 2) {
            if (!validationRules.uppercase.test(password)) {
                feedback.push('Add at least one uppercase letter');
            }
            if (!validationRules.lowercase.test(password)) {
                feedback.push('Add at least one lowercase letter');
            }
            if (!validationRules.number.test(password)) {
                feedback.push('Add at least one number');
            }
            if (!validationRules.special.test(password)) {
                feedback.push('Add at least one special character');
            }
            if (password.length < validationRules.minLength) {
                feedback.push(`Password should be at least ${validationRules.minLength} characters long`);
            }
        }

        // Add warning only for very weak passwords
        // This helps users understand why their password is weak
        if (isPasswordTooCommon(password)) {
            feedback.push('This password is too common or can be cracked quickly. Consider using a more unique combination.');
        }

        return feedback;
    }

    // Update the UI with password strength information
    // Provides real-time feedback as the user types
    function updatePasswordStrength(password) {
        const result = zxcvbn(password);
        
        // Update visual strength indicator
        const config = strengthConfig[result.score];
        strengthBar.style.backgroundColor = config.color;
        strengthBar.style.width = config.width;
        strengthLabel.textContent = config.label;
        strengthLabel.style.color = config.color;

        // Show estimated crack time
        crackTime.textContent = result.crack_times_display.offline_fast_hashing_1e10_per_second;

        // Display any security warnings
        warnings.textContent = result.feedback.warning || 'No warnings';

        // Show improvement suggestions
        suggestions.innerHTML = '';
        const allSuggestions = [
            ...getValidationFeedback(password),
            ...result.feedback.suggestions
        ];

        if (allSuggestions.length > 0) {
            allSuggestions.forEach(suggestion => {
                const li = document.createElement('li');
                li.textContent = suggestion;
                suggestions.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = 'No suggestions available';
            suggestions.appendChild(li);
        }
    }

    // Handle real-time password input
    // Updates feedback as the user types
    passwordInput.addEventListener('input', (e) => {
        const password = e.target.value;
        if (password.length > 0) {
            updatePasswordStrength(password);
        } else {
            // Reset UI when password is empty
            strengthBar.style.width = '0';
            strengthLabel.textContent = 'Very Weak';
            strengthLabel.style.color = 'var(--text-color)';
            crackTime.textContent = '-';
            warnings.textContent = '-';
            suggestions.innerHTML = '';
        }
    });
}); 