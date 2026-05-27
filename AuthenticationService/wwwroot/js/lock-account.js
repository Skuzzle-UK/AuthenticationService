// Auto-fires on page load — the page is reached via a "wasn't me!" email link and the
// user expects the lock to happen immediately.
(function () {
    const pageData = document.getElementById('page-data');
    if (!pageData) return;

    const token = pageData.dataset.token;
    const email = pageData.dataset.email;

    document.addEventListener('DOMContentLoaded', async () => {
        const response = await fetch('api/account/lock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ Email: email, Token: token })
        }).catch(error => {
            console.error('Error:', error);
            alert('Network error — please try again.');
        });

        if (!response) return;

        if (response.status === 200) {
            alert('Account locked');
            setTimeout(() => { window.location.href = '/ActionComplete'; }, 1000);
            return;
        }

        const body = await response.json().catch(() => null);
        alert('Account lock failed:\n' + formatErrors(body));
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
