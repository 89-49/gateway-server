import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.1/index.js';

// 환경변수
// 실행 방법:
// k6 run --env NGINX_IP=34.64.xxx.xxx test2-max-users.js

const BASE_URL = `http://${__ENV.NGINX_IP}`;

const errorRate = new Rate('error_rate');
const latency   = new Trend('latency_ms', true);

export const options = {
    stages: [
        { duration: '20s', target: 100 }, // Ramp-Up → 100명
        { duration: '1m',  target: 100 }, // 유지
        { duration: '20s', target: 0   }, // Ramp-Down
        { duration: '20s', target: 200 }, // Ramp-Up → 200명
        { duration: '1m',  target: 200 }, // 유지
        { duration: '20s', target: 0   }, // Ramp-Down
        { duration: '20s', target: 300 }, // Ramp-Up → 300명
        { duration: '1m',  target: 300 }, // 유지
        { duration: '20s', target: 0   }, // Ramp-Down
        { duration: '20s', target: 400 }, // Ramp-Up → 400명
        { duration: '1m',  target: 400 }, // 유지
        { duration: '20s', target: 0   }, // Ramp-Down
        { duration: '20s', target: 500 }, // Ramp-Up → 500명
        { duration: '1m',  target: 500 }, // 유지
        { duration: '20s', target: 0   }, // Ramp-Down
    ],
    thresholds: {
        'error_rate':        [{ threshold: 'rate<0.05',  abortOnFail: true }],
        'http_req_duration': [{ threshold: 'p(95)<3000', abortOnFail: true }],
    },
};

// setup()에서 토큰 1개 발급 후 전체 VU 재사용
export function setup() {
    const res = http.post(
        `${BASE_URL}/api/v1/auth/login`,
        JSON.stringify({ username: 'user00001', password: 'password' }),
        { headers: { 'Content-Type': 'application/json' } }
    );

    const body = res.json();
    if (!body.success || !body.data.accessToken) {
        throw new Error(`로그인 실패: ${res.body}`);
    }

    console.log('토큰 발급 완료 (최대 동시 접속자 수 탐색)');
    return { token: body.data.accessToken };
}

export default function (data) {
    const res = http.get(`${BASE_URL}/api/v1/users/me`, {
        headers: { Authorization: data.token },
        timeout: '15s',
    });

    const ok = check(res, {
        'status 200':       (r) => r.status === 200,
        'latency < 3000ms': (r) => r.timings.duration < 3000,
    });

    latency.add(res.timings.duration);
    errorRate.add(!ok);
}

export function handleSummary(data) {
    return {
        'result/result-test2-max-users.json': JSON.stringify(data, null, 2),
        stdout: textSummary(data, { indent: ' ', enableColors: true }),
    };
}