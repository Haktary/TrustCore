document.getElementById('savePasswordsForm').addEventListener('submit', function(event) {
    event.preventDefault();

    var formData = {
        passwords: document.getElementById('passwords').value.split(',').map(password => password.trim())
    };

    fetch('api/save-passwords', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
    })
        .then(response => response.json())
        .then(data => {
            document.getElementById('resultContainer').innerText = data.success ? 'Mots de passe sauvegardés!' : 'Erreur: ' + data.error;
        })
        .catch(error => console.error('Erreur:', error));
});

document.getElementById('decryptPasswords').addEventListener('click', function() {
    fetch('api/decrypt-passwords', {
        method: 'POST'
    })
        .then(response => response.json())
        .then(data => {
            if (data.success && data.data) {
                document.getElementById('resultContainer').innerHTML = '<h3>Mots de passe décryptés:</h3><ul>' + data.data.map(password => '<li>' + password + '</li>').join('') + '</ul>';
            } else {
                document.getElementById('resultContainer').innerText = 'Erreur: ' + data.error;
            }
        })
        .catch(error => console.error('Erreur:', error));
});

document.getElementById('logout').addEventListener('click', function() {
    document.cookie = "session_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
    window.location.href = 'login.html';
});

document.getElementById('generatePassword').addEventListener('click', function() {
    fetch('api/generate-password', {
        method: 'POST'
    })
        .then(response => response.json())
        .then(data => {
            if (data.success && data.data) {
                document.getElementById('resultContainer').innerText = 'Mot de passe généré: ' + data.data;
            } else {
                document.getElementById('resultContainer').innerText = 'Erreur: ' + data.error;
            }
        })
        .catch(error => console.error('Erreur:', error));
});