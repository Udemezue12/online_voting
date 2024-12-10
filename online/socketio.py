from flask_socketio import Namespace, emit

class ResultsNamespace(Namespace):
    def on_connect(self):
        print('Client connected to /results')

    def on_disconnect(self):
        print('Client disconnected from /results')

    def on_custom_event(self, data):
        # Handle custom events if needed
        print(f'Received data: {data}')
        emit('response', {'message': 'Event received!'})
