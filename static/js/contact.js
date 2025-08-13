document.addEventListener('DOMContentLoaded', () => {
    const contactForm = document.getElementById('contactForm');
    if (!contactForm) return; // Don't run if the form isn't on the page

    const messageDiv = document.getElementById('message');

    contactForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = e.target.name.value;
        const email = e.target.email.value;
        const phone = e.target.phone.value;
        const message = e.target.message.value;

        try {
            const response = await fetch('/submit_contact', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, phone, message })
            });

            // Check if the response is ok (status in the range 200-299)
            if (!response.ok) {
                // Try to get error message from server, or use default
                let errorMessage = `Error: ${response.status} ${response.statusText}`;
                try {
                    const errorResult = await response.json();
                    errorMessage = errorResult.message || errorMessage;
                } catch (jsonError) {
                    // Response was not JSON, do nothing
                }
                throw new Error(errorMessage);
            }

            const result = await response.json();
            showMessage(result.message, result.success);

            if (result.success) {
                // Only reset the message field, since name/email are readonly
                e.target.message.value = '';
            }
        } catch (error) {
            console.error('Fetch error:', error);
            showMessage('A network error occurred. Please try again.', false);
        }
    });

    function showMessage(message, isSuccess) {
        messageDiv.textContent = message;
        messageDiv.classList.remove('success', 'error');
        messageDiv.classList.add(isSuccess ? 'success' : 'error');
        messageDiv.style.display = 'block';
    }
});