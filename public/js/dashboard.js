// Fetch user details when the page loads
    document.addEventListener('DOMContentLoaded', function () {
        fetchUserDetails();
    });

    async function fetchUserDetails() {
        try {
            const response = await fetch('/user-details', { credentials: 'include' });
            if (!response.ok) {
                throw new Error('Failed to fetch user details.');
            }
            const data = await response.json();
            if (data.success) {
                // Update the element with user email
                document.getElementById('userEmail').textContent = data.user.email;
            } else {
                console.error('Failed to fetch user details:', data.message);
            }
        } catch (error) {
            console.error('Error fetching user details:', error);
        }
    }

    // Add logout functionality
    document.getElementById('logoutLink').addEventListener('click', function (event) {
        event.preventDefault();
        performLogout();
    });

    async function performLogout() {
        try {
            const response = await fetch('/logout', {
                method: 'POST',
                credentials: 'include'
            });

            if (response.ok) {
                // Redirect to login page
                window.location.href = 'index.html';
            } else {
                console.error('Logout failed');
            }
        } catch (error) {
            console.error('Error during logout:', error);
        }
    }

    // Top-up form submission
    document.getElementById('topUpForm').addEventListener('submit', function (event) {
        event.preventDefault();
        
        const amount = document.getElementById('amount').value.trim();
        const paymentMethod = document.getElementById('paymentMethod').value;

        if (!amount || !paymentMethod) {
            document.getElementById('topUpError').textContent = 'Please fill in all fields.';
            return;
        }

        // Clear previous messages
        document.getElementById('topUpError').textContent = '';
        document.getElementById('topUpSuccess').textContent = '';

        // Simulate top-up process (in real scenarios, this would be a server request)
        fetch('/top-up', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount: amount, paymentMethod: paymentMethod }),
            credentials: 'include'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.getElementById('topUpSuccess').textContent = `Top-up successful! You added ${amount} using ${paymentMethod}.`;
            } else {
                document.getElementById('topUpError').textContent = `Top-up failed: ${data.message}`;
            }
        })
        .catch(error => {
            console.error('Error during top-up:', error);
            document.getElementById('topUpError').textContent = 'An error occurred during top-up.';
        });
    });