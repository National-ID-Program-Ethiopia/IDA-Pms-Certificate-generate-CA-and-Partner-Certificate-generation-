from flask import Flask, render_template, request, send_file
import io
from cert_utils import generate_ca_cert, generate_intermediate_cert, generate_partner_cert

app = Flask(__name__)

ca_key_pem = None
ca_cert_pem = None
int_key_pem = None
int_cert_pem = None

@app.route('/')
def index():
    return render_template('certificate_gen.html')

@app.route('/generate_ca', methods=['POST'])
def generate_ca():
    global ca_key_pem, ca_cert_pem
    country_code_ca = request.form['country_code_ca']
    province_ca = request.form['province_ca']
    locality_ca = request.form['locality_ca']
    organization_ca = request.form['organization_ca']
    common_name_ca = request.form['common_name_ca']
    
    ca_key_pem, ca_cert_pem = generate_ca_cert(
        country_code_ca, province_ca, locality_ca, organization_ca, common_name_ca
    )
    
    # Dynamic download name based on organization name
    download_name = f"{organization_ca}_CA_cert.crt"
    
    return send_file(io.BytesIO(ca_cert_pem), as_attachment=True, download_name=download_name,
                     mimetype="application/x-x509-ca-cert")

@app.route('/generate_intermediate', methods=['POST'])
def generate_intermediate():
    global int_key_pem, int_cert_pem
    if not ca_key_pem or not ca_cert_pem:
        return "CA Certificate must be generated first.", 400

    country_code_int = request.form['country_code_int']
    province_int = request.form['province_int']
    locality_int = request.form['locality_int']
    org_name_int = request.form['org_name_int']
    common_name_int = request.form['common_name_int']

    int_key_pem, int_cert_pem = generate_intermediate_cert(
        ca_key_pem, ca_cert_pem,
        country_code_int, province_int,
        locality_int, org_name_int, common_name_int
    )

    # Dynamic download name based on organization name
    download_name = f"{org_name_int}_Intermediate_cert.crt"

    return send_file(io.BytesIO(int_cert_pem), as_attachment=True, download_name=download_name,
                     mimetype="application/x-x509-ca-cert")

@app.route('/generate_partner', methods=['POST'])
def generate_partner():
    if not int_key_pem or not int_cert_pem:
        return "Intermediate Certificate must be generated first.", 400

    country_code_part = request.form['country_code_part']
    province_part = request.form['province_part']
    locality_part = request.form['locality_part']
    org_name_part = request.form['org_name_part']
    common_name_part = request.form['common_name_part']

    partner_key_pem, partner_cert_pem = generate_partner_cert(
        int_key_pem, int_cert_pem,
        country_code_part, province_part,
        locality_part, org_name_part, common_name_part
    )

    # Dynamic download name based on organization name
    download_name = f"{org_name_part}_Partner_cert.crt"

    return send_file(io.BytesIO(partner_cert_pem), as_attachment=True, download_name=download_name,
                     mimetype="application/x-x509-ca-cert")

if __name__ == '__main__':
    app.run(debug=True)
