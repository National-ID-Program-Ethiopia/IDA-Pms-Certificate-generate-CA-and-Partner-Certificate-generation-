from flask import Flask, render_template, request, send_file
import os
from cert_utils import generate_ca_cert, generate_partner_cert
import io

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('certificate_gen.html')


@app.route('/generate_ca', methods=['POST'])
def generate_ca():
    country_code_ca = request.form['country_code_ca']
    province_ca = request.form['province_ca']
    locality_ca = request.form['locality_ca']
    organization_ca = request.form['organization_ca']
    common_name_ca = request.form['common_name_ca']

    ca_key_pem, ca_cert_pem = generate_ca_cert(
        country_code_ca, province_ca, locality_ca, organization_ca, common_name_ca
    )

    ca_cert_file = io.BytesIO(ca_cert_pem)
    ca_cert_file.seek(0)

    return send_file(ca_cert_file, as_attachment=True, download_name=f"{organization_ca}_CA_cert.crt", mimetype="application/x-x509-ca-cert")


@app.route('/generate_partner', methods=['POST'])
def generate_partner():
    country_code_part = request.form['country_code_part']
    province_part = request.form['province_part']
    locality_part = request.form['locality_part']
    org_name_part = request.form['org_name_part']
    common_name_part = request.form['common_name_part']

    # Generate a new CA certificate every time (or load from an actual stored CA cert)
    ca_key_pem, ca_cert_pem = generate_ca_cert("US", "California", "San Francisco", "Example CA", "example.com")

    partner_key_pem, partner_cert_pem = generate_partner_cert(
        country_code_part, province_part, locality_part, org_name_part, common_name_part, ca_key_pem, ca_cert_pem
    )

    partner_cert_file = io.BytesIO(partner_cert_pem)
    partner_cert_file.seek(0)

    return send_file(partner_cert_file, as_attachment=True, download_name=f"{org_name_part}_Partner_cert.crt", mimetype="application/x-x509-ca-cert")


if __name__ == '__main__':
    app.run(debug=True)
