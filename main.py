import os
#import magic
import urllib.request
from app import app
from flask import Flask, flash, request, redirect, render_template, send_from_directory
from werkzeug.utils import secure_filename
from subprocess import check_output
import time

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'pcap'])
basedir = os.path.abspath(os.path.dirname(__file__))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def convert_to_csv(filename):
    with open("static/" + filename) as infile, open("static/" + filename[:-4] + "csv", 'w') as outfile:
        outfile.write("num_conn,startTimet,orig_pt,resp_pt,orig_ht,resp_ht,duration,protocol,resp_pt,flag,src_bytes,dst_bytes,land,wrong_fragment,urg,hot,num_failed_logins,logged_in,num_compromised,root_shell,su_attempted,num_root,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_hot_login,is_guest_login,count_sec,srv_count_sec,serror_rate_sec,srv_serror_rate_sec,rerror_rate_sec,srv_error_rate_sec,same_srv_rate_sec,diff_srv_rate_sec,srv_diff_host_rate_sec,count_100,srv_count_100,same_srv_rate_100,diff_srv_rate_100,same_src_port_rate_100,srv_diff_host_rate_100,serror_rate_100,srv_serror_rate_100,rerror_rate_100,srv_rerror_rate_100\n")
        for line in infile:
            outfile.write(" ".join(line.split()).replace(' ', ','))
            outfile.write(",\n") # trailing comma shouldn't matter


def convert_to_kdd_format(filename):
    outfile = filename[:-4] + "list"
    cmd = ['./createAttrib.sh', filename, outfile]
    out = check_output(cmd).decode('utf-8')
    
    # conn.log file will be created
    while not os.path.exists("./static/" + outfile):
        time.sleep(1)

    convert_to_csv(outfile)


@app.route('/')
def upload_form():
    return render_template('upload.html')

@app.route('/<path:filename>', methods=['GET'])
def download(filename):
    return send_from_directory(app.static_folder, filename, as_attachment=True)

@app.route('/', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_as = os.path.join(basedir, app.config['UPLOAD_FOLDER'], filename)
            file.save(save_as)
            flash('File successfully uploaded')
            convert_to_kdd_format(filename)
            return redirect('/' + filename[:-4] + "csv")
        else:
            flash('Allowed file types are txt, pdf, png, jpg, jpeg, gif, pcap')
            return redirect(request.url)

if __name__ == "__main__":
    app.run()