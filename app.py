import os
import subprocess
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__, static_folder='.', static_url_path='')
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/run-script', methods=['POST'])
def run_script():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    script_id = request.form.get('scriptId')
    source_type = request.form.get('sourceType', '') # For 06_siem
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Map scriptId to command
        cmd = []
        if script_id == '01':
            cmd = ['python3', '01_log_breach_detector.py', '--log', filepath]
        elif script_id == '02':
            cmd = ['python3', '02_win_event_analyzer.py', '--evtx', filepath]
        elif script_id == '03':
            cmd = ['python3', '03_net_analyzer.py', '--pcap', filepath]
        elif script_id == '04':
            cmd = ['python3', '04_alert_triage.py', '--alerts', filepath]
        elif script_id == '05':
            cmd = ['python3', '05_phish_detector.py', '--eml', filepath]
        elif script_id == '06':
            if not source_type:
                source_type = 'syslog' # default
            cmd = ['python3', '06_siem.py', '--log', filepath, '--source', source_type]
        else:
            return jsonify({'error': 'Unknown script ID'}), 400
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout + "\n" + result.stderr
            return jsonify({'output': output.strip(), 'status': 'success'})
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Execution timed out', 'status': 'error'}), 500
        except Exception as e:
            return jsonify({'error': str(e), 'status': 'error'}), 500
            
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
