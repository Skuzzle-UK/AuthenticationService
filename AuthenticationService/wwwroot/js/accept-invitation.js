(function () {
    const pageData = document.getElementById('page-data');
    if (!pageData) return;

    const token = pageData.dataset.token;
    const email = pageData.dataset.email;
    const callbackUri = pageData.dataset.callbackUri;

    document.getElementById('activate-button').addEventListener('click', async () => {
        const newPassword = document.getElementById('NewPassword').value;
        const confirmPassword = document.getElementById('ConfirmPassword').value;

        if (newPassword !== confirmPassword) {
            alert('Passwords do not match.');
            return;
        }

        const response = await fetch('api/registration/accept-invitation', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                Email: email,
                NewPassword: newPassword,
                Token: token,
                CallbackUri: callbackUri
            })
        }).catch(error => {
            console.error('Error:', error);
            alert('Network error — please try again.');
        });

        if (!response) return;

        if (response.ok) {
            alert('Your account is active. You can now sign in.');
            const body = await response.json().catch(() => null);
            const redirect = (body && body.redirect) || '/ActionComplete';
            setTimeout(() => { window.location.href = redirect; }, 1000);
            return;
        }

        const body = await response.json().catch(() => ({}));
        let errorMessages = '';
        if (body && body.errors) {
            for (const key in body.errors) {
                errorMessages += body.errors[key] + '\n';
            }
        }
        alert('Failed to activate account:\n' + (errorMessages || 'Unknown error'));
    });
})();
