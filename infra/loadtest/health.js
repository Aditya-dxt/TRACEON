import http from 'k6/http';
import { check } from 'k6';

const baseUrl = __ENV.TRACEON_BASE_URL || 'http://localhost:8000';

export const options = {
  scenarios: {
    health_smoke: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS || 2),
      duration: __ENV.DURATION || '30s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500'],
  },
};

export default function () {
  const response = http.get(`${baseUrl}/v1/health`);
  check(response, {
    'health responds 200': (res) => res.status === 200,
    'health response is JSON ok': (res) => res.json('status') === 'ok',
  });
}
