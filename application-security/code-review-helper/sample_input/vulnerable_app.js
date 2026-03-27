/**
 * Vulnerable Demo Application — FOR TESTING ONLY.
 * This file intentionally contains security vulnerabilities for code-review-helper sample_input.
 * DO NOT deploy or use this code in any real application.
 */

const express = require('express');
const app = express();

// Vulnerability 1: eval() usage (CWE-95)
function calculateExpression(userInput) {
    return eval(userInput);
}

// Vulnerability 2: innerHTML XSS (CWE-79)
function renderUserContent(data) {
    const container = document.getElementById('content');
    container.innerHTML = data.userMessage;
}

// Vulnerability 3: document.write XSS (CWE-79)
function loadExternalContent(url) {
    document.write('<script src="' + url + '"></script>');
}

// Vulnerability 4: Sensitive data in localStorage (CWE-922)
function saveSession(token, userId) {
    localStorage.setItem('auth_token', token);
    localStorage.setItem('password', userId);
    localStorage.setItem('secret_key', 'abc123');
}

// Vulnerability 5: Prototype pollution (CWE-1321)
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            // Dangerous: allows __proto__ pollution
            target.__proto__[key] = source[key];
        }
    }
    return target;
}

// Vulnerability 6: dangerouslySetInnerHTML in React component (CWE-79)
function UserComment({ comment }) {
    return React.createElement('div', {
        dangerouslySetInnerHTML: { __html: comment.content }
    });
}

// Vulnerability 7: Open redirect (CWE-601)
app.get('/redirect', (req, res) => {
    const target = req.query.url;
    // User-controlled redirect destination
    window.location = req.query.next;
    res.redirect(target);
});

// Vulnerability 8: ReDoS via complex regex (CWE-1333)
function validateEmail(email) {
    const emailRegex = /^([a-zA-Z0-9]+(\.+[a-zA-Z0-9]+)*)+@[a-zA-Z0-9]+(\.+[a-zA-Z0-9]+)*$/;
    return new RegExp(emailRegex).test(email);
}

app.listen(3000);
