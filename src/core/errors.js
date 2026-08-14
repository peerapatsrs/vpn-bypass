'use strict';

class AppError extends Error {
  constructor(code, message, extra = {}) {
    super(message || code);
    this.name = 'AppError';
    this.code = code;
    this.extra = extra;
    this.http = extra.http;
  }
}

function fail(code, message, extra) {
  return new AppError(code, message, extra);
}

function httpStatus(code) {
  switch (code) {
    case 'EAUTH':
      return 401;
    case 'EPRIV':
    case 'EORIGIN':
    case 'EPERM':
      return 403;
    case 'EINVAL':
    case 'EBLOCKED':
    case 'EDOMAIN_EMPTY':
    case 'ENOTLOOPBACK':
      return 400;
    case 'ENOTVPN':
    case 'ENOLAN':
    case 'ELOCK':
    case 'ENOTAPPLIED':
      return 409;
    case 'EUNSUPPORTED':
      return 501;
    default:
      return 500;
  }
}

module.exports = { AppError, fail, httpStatus };
