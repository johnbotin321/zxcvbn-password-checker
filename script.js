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

    // Calculate actual strength score based on zxcvbn score and crack time
    function calculateActualStrength(result) {
        let zxcvbnScore = result.score;
        const crackTimeSeconds = result.crack_times_seconds.offline_fast_hashing_1e10_per_second;

        let strengthScoreBasedOnTime = 0; // Default to Very Weak

        // Define crack time thresholds in seconds for clear comparison
        const ONE_MINUTE_SECONDS = 60;
        const ONE_HOUR_SECONDS = 3600;
        const ONE_MONTH_SECONDS = 2592000; // Approximately 30 days (30 * 24 * 3600)
        const TEN_YEARS_SECONDS = 315360000; // Approximately 10 years (10 * 365.25 * 24 * 3600)

        // Determine the maximum possible strength score based solely on crack time.
        // The checks are ordered from longest crack time to shortest.
        if (crackTimeSeconds >= TEN_YEARS_SECONDS) {
            strengthScoreBasedOnTime = 4; // Can be Very Strong
        } else if (crackTimeSeconds >= ONE_MONTH_SECONDS) {
            strengthScoreBasedOnTime = 3; // Can be Strong
        } else if (crackTimeSeconds >= ONE_HOUR_SECONDS) {
            strengthScoreBasedOnTime = 2; // Can be Moderate
        } else if (crackTimeSeconds >= ONE_MINUTE_SECONDS) {
            strengthScoreBasedOnTime = 1; // Can be Weak
        } else { 
            // If crackTimeSeconds is less than ONE_MINUTE_SECONDS
            strengthScoreBasedOnTime = 0; // Very Weak
        }

        // The final score is the minimum of zxcvbn's score and our time-based score.
        // This ensures that a password isn't rated higher than its weakest characteristic (either complexity or crack time).
        return Math.min(zxcvbnScore, strengthScoreBasedOnTime);
    }

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
        const crackTimeSeconds = result.crack_times_seconds.offline_fast_hashing_1e10_per_second;
        // Consider passwords weak if they score low or can be cracked quickly (less than 1 day)
        return result.score < 2 || crackTimeSeconds < 86400;
    }

    // Verify if password has sufficient crack time (at least a decade)
    // This ensures passwords are resistant to brute force attacks
    function hasSufficientCrackTime(password) {
        const result = zxcvbn(password);
        const crackTimeSeconds = result.crack_times_seconds.offline_fast_hashing_1e10_per_second;
        // A decade is 10 years, which is approximately 315,360,000 seconds
        return crackTimeSeconds >= 315360000;
    }

    // Enhance a moderate password to make it significantly stronger
    // Uses multiple techniques to increase entropy and complexity
    // This function now guarantees to return an enhanced string based on the input,
    // and its actual strength will be assessed by calculateActualStrength afterwards.
    function enhanceModeratePassword(password) {
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

        return enhancedPassword;
    }

    // Generate a stronger version of the current password
    // Always attempts to enhance weak to moderate passwords, and the actual strength
    // of the generated password is then assessed and displayed.
    function generateSimilarPassword(originalPassword) {
        if (!originalPassword) return '';

        const result = zxcvbn(originalPassword);
        const actualScore = calculateActualStrength(result);

        // If the password is already strong (score 3 or 4), no need to suggest a new one.
        // This prevents unnecessary complexity when the password is already secure.
        if (actualScore >= 3) {
            return null; // Return null to indicate no suggestion is needed/possible
        }

        // For Very Weak (score 0), Weak (score 1), and Moderate (score 2) passwords,
        // always attempt to enhance them to a stronger version.
        // The strength of the generated password will be evaluated and displayed
        // by updatePasswordStrength.
        const enhancedPassword = enhanceModeratePassword(originalPassword);
        return enhancedPassword; // Always return the enhanced string
    }

    // Handle password suggestion button clicks
    // Provides appropriate feedback based on password strength and suggestion outcome
    suggestPasswordBtn.addEventListener('click', () => {
        const currentPassword = passwordInput.value;
        if (currentPassword) {
            const result = zxcvbn(currentPassword); // Get initial result for current password
            const actualScore = calculateActualStrength(result); // Get initial actual score

            // If the current password is already strong, no suggestion is needed/possible
            if (actualScore >= 3) {
                warnings.textContent = "Your password is already strong! No suggestions needed.";
                suggestions.innerHTML = `
                    <li>Keep using this strong password</li>
                    <li>Make sure to use different strong passwords for different accounts</li>
                `;
                return;
            }

            // Attempt to generate a similar, stronger password
            const suggestedPassword = generateSimilarPassword(currentPassword);

            // If a suggestion was successfully generated, update the input and UI
            if (suggestedPassword) { // Check for truthiness instead of === null
                passwordInput.value = suggestedPassword;
                updatePasswordStrength(suggestedPassword); // This will re-evaluate and display warnings if the SUGGESTED password is still not decade-long
            } else {
                // This block is only hit if generateSimilarPassword explicitly returned null,
                // which now only happens if the original password was already strong.
                // However, as a fallback, we can add this for clarity if logic changes.
                warnings.textContent = "Unable to create a suitable stronger version. Please try a different base password.";
                suggestions.innerHTML = `
                    <li>Try using a longer base password</li>
                    <li>Use a combination of unrelated words</li>
                    <li>Consider using a passphrase with special characters</li>
                `;
            }
        }
    });

    // Validate password against security requirements
    // Provides specific feedback for weak passwords
    function getValidationFeedback(password) {
        const feedback = [];
        const result = zxcvbn(password);
        const actualScore = calculateActualStrength(result);
        
        // Only show basic validation feedback for weak passwords
        // This prevents cluttering the interface for strong passwords
        if (actualScore < 2) {
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
        console.log("zxcvbn result for '" + password + "':", result);
        const actualScore = calculateActualStrength(result);
        
        // Update visual strength indicator
        const config = strengthConfig[actualScore];
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
