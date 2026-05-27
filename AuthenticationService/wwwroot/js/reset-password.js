// External JS so the page can be served under a strict CSP (no 'unsafe-inline').
// Server-side state (token, email) arrives via data-* attributes on #page-data.
(function () {
    const pageData = document.getElementById('page-data');
    if (!pageData) return;

    const token = pageData.dataset.token;
    const email = pageData.dataset.email;

    document.getElementById('reset-button').addEventListener('click', async () => {
        const newPassword = document.getElementById('NewPassword').value;
        const confirmPassword = document.getElementById('ConfirmPassword').value;

        const response = await fetch('api/account/forgotpassword/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                Email: email,
                NewPassword: newPassword,
                ConfirmPassword: confirmPassword,
                Token: token,
                CallbackUri: '/ActionComplete'
            })
        }).catch(error => {
            console.error('Error:', error);
            alert('Network error — please try again.');
        });

        if (!response) return;

        if (response.status === 200) {
            alert('Password reset successfully');
            setTimeout(() => { window.location.href = '/ActionComplete'; }, 1000);
            return;
        }

        const body = await response.json().catch(() => null);
        alert('Password reset failed:\n' + formatErrors(body));
    });

    function formatErrors(body) {
        if (!body || !body.errors) return 'Unknown error';
        if (Array.isArray(body.errors)) return body.errors.join(' ');
        const lines = [];
        for (const key in body.errors) {
            const v = body.errors[key];
            lines.push(Array.isArray(v) ? v.join(' ') : v);
        }
        return lines.join('\n');
    }
})();
