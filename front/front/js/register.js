document.getElementById('registerForm').addEventListener('submit', function(event) {
    event.preventDefault();

    var formData = {
        name: document.getElementById('name').value,
        email: document.getElementById('email').value,
        password: document.getElementById('password').value
    };

    fetch('api/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
    })
        .then(response => response.json())
        .then(data => {
            document.getElementById('resultContainer').innerText = data.success ? 'Inscription réussie!' : 'Erreur: ' + data.error;
            if (data.success) {
                setTimeout(() => window.location.href = 'login.html', 2000);
            }
        })
        .catch(error => console.error('Erreur:', error));
});
