from flask import Blueprint, render_template

error_pages = Blueprint('error_pages', __name__)

@error_pages.app_errorhandler(401)
def unauthorized_error(error):
    return render_template('error_pages/401.html'), 401

@error_pages.app_errorhandler(400)
def bad_request(error):
    return render_template('error_pages/400.html'), 400


@error_pages.app_errorhandler(403)
def forbidden(error):
    return render_template('error_pages/403.html'), 403
@error_pages.app_errorhandler(404)
def page_not_found(error):
    return render_template("error_pages/404.html"), 404

@error_pages.app_errorhandler(405)
def method_not_allowed_error(error):
    return render_template('error_pages/405.html'), 405


@error_pages.app_errorhandler(406)
def not_acceptable_error(error):
    return render_template('error_pages/406.html'), 406





@error_pages.app_errorhandler(408)
def request_timeout_error(error):
    return render_template('error_pages/408.html'), 408


@error_pages.app_errorhandler(409)
def conflict_error(error):
    return render_template('error_pages/409.html'), 409


@error_pages.app_errorhandler(410)
def gone_error(error):
    return render_template('error_pages/410.html'), 410


@error_pages.app_errorhandler(411)
def length_required_error(error):
    return render_template('error_pages/411.html'), 411


@error_pages.app_errorhandler(412)
def precondition_failed_error(error):
    return render_template('error_pages/412.html'), 412


@error_pages.app_errorhandler(413)
def payload_too_large_error(error):
    return render_template('error_pages/413.html'), 413


@error_pages.app_errorhandler(414)
def uri_too_long_error(error):
    return render_template('error_pages/414.html'), 414


@error_pages.app_errorhandler(415)
def unsupported_media_type_error(error):
    return render_template('error_pages/415.html'), 415


@error_pages.app_errorhandler(416)
def range_not_satisfiable_error(error):
    return render_template('error_pages/416.html'), 416


@error_pages.app_errorhandler(417)
def expectation_failed_error(error):
    return render_template('error_pages/417.html'), 417


@error_pages.app_errorhandler(418)
def im_a_teapot_error(error):
    return render_template('error_pages/418.html'), 418





@error_pages.app_errorhandler(422)
def unprocessable_entity_error(error):
    return render_template('error_pages/422.html'), 422


@error_pages.app_errorhandler(423)
def locked_error(error):
    return render_template('error_pages/423.html'), 423


@error_pages.app_errorhandler(424)
def failed_dependency_error(error):
    return render_template('error_pages/424.html'), 424




@error_pages.app_errorhandler(428)
def precondition_required_error(error):
    return render_template('error_pages/428.html'), 428


@error_pages.app_errorhandler(429)
def too_many_requests_error(error):
    return render_template('error_pages/429.html'), 429


@error_pages.app_errorhandler(431)
def request_header_fields_too_large_error(error):
    return render_template('error_pages/431.html'), 431


@error_pages.app_errorhandler(451)
def unavailable_for_legal_reasons_error(error):
    return render_template('error_pages/451.html'), 451


@error_pages.app_errorhandler(500)
def internal_server_error(error):
    return render_template('error_pages/500.html'), 500


@error_pages.app_errorhandler(501)
def not_implemented_error(error):
    return render_template('error_pages/501.html'), 501


@error_pages.app_errorhandler(502)
def bad_gateway_error(error):
    return render_template('error_pages/502.html'), 502


@error_pages.app_errorhandler(503)
def service_unavailable_error(error):
    return render_template('error_pages/503.html'), 503


@error_pages.app_errorhandler(504)
def gateway_timeout_error(error):
    return render_template('error_pages/504.html'), 504


@error_pages.app_errorhandler(505)
def http_version_not_supported_error(error):
    return render_template('error_pages/505.html'), 505