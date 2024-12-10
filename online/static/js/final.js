const socket = io('/results');

const candidatesContainer = document.getElementById('candidates');

function renderCandidates(candidates) {
    candidatesContainer.innerHTML = ''; 

    Object.entries(candidates).forEach(([name, voteCount]) => {
        const candidateCard = document.createElement('div');
        candidateCard.className = 'candidate-card';

        candidateCard.innerHTML = `
            <h3>${name}</h3>
            <p>Votes: <span class="vote-count">${voteCount}</span></p>
        `;

        candidatesContainer.appendChild(candidateCard);
    });
}

socket.on('connect', () => {
    console.log('Connected to the WebSocket server.');

    socket.emit('request_initial_results');
});

// Listen for disconnection
socket.on('disconnect', () => {
    console.log('Disconnected from the WebSocket server.');
});

socket.on('update_results', (data) => {
    console.log('Received updated results:', data);

    renderCandidates(data);
});

socket.on('connect_error', (error) => {
    console.error('WebSocket connection error:', error);
    alert('WebSocket connection failed. Some features may not work as expected.');
});

document.addEventListener('DOMContentLoaded', () => {
    fetch('/api/candidates') 
        .then((response) => response.json())
        .then((data) => {
            renderCandidates(data);
        })
        .catch((error) => {
            console.error('Failed to fetch initial candidates:', error);
        });
});
