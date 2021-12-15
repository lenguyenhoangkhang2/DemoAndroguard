from flask import Flask, render_template, request
from androguard.misc import AnalyzeAPK

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["GET", "POST"])
def analyzeAPK():
    if request.method == "POST":
        fileApk = request.files["fileApk"].read()

        a, d, dx = AnalyzeAPK(fileApk, raw=True)

        return render_template(
            "analyze.html",
            apkName=a.get_app_name(),
            permissions=a.get_permissions(),
            activities=a.get_activities(),
            internalClasses=dx.get_internal_classes(),
            externalClasses=dx.get_external_classes(),
            package=a.get_package(),
            isSigned=a.is_signed(),
            isSigned1=a.is_signed_v1(),
            isSigned2=a.is_signed_v2(),
            certs=a.get_certificates(),
        )
    else:
        return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
