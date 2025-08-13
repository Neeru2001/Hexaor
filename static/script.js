document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('register-form');
    const messageEl = document.getElementById('message');

    form.addEventListener('submit', async (event) => {
        event.preventDefault(); // Prevent default form submission

        const username = form.username.value;
        const password = form.password.value;

        const response = await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        const result = await response.json();

        if (result.success) {
            messageEl.style.color = 'green';
            messageEl.textContent = result.message;
            form.reset(); // Clear the form
        } else {
            messageEl.style.color = 'red';
            messageEl.textContent = result.message;
        }
    });
});