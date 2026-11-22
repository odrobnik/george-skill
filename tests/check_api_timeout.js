// Execute the production request function with offline fetch doubles that respect cancellation.
const assert = require('node:assert/strict');
const fs = require('node:fs');

async function main() {
    const {source, args, scenario} = JSON.parse(fs.readFileSync(0, 'utf8'));
    const request = eval(`(${source})`);
    const timers = new Set();
    const originalSetTimeout = global.setTimeout;
    const originalClearTimeout = global.clearTimeout;
    global.setTimeout = (callback, delay) => {
        const timer = originalSetTimeout(callback, delay);
        timers.add(timer);
        return timer;
    };
    global.clearTimeout = timer => {
        timers.delete(timer);
        originalClearTimeout(timer);
    };

    let signal;
    function untilAborted() {
        return new Promise((resolve, reject) => {
            const abort = () => reject(new DOMException('The operation was aborted', 'AbortError'));
            if (signal.aborted) abort();
            else signal.addEventListener('abort', abort, {once: true});
        });
    }
    global.fetch = async (url, options) => {
        assert.equal(url, args[1]);
        assert.equal(options.method, 'POST');
        assert.equal(options.headers.Authorization, 'test-token');
        assert.deepEqual(JSON.parse(options.body), {amount: 1234});
        signal = options.signal;
        assert.ok(signal instanceof AbortSignal);
        if (scenario === 'fetch_stall') await untilAborted();
        if (scenario === 'error') throw new Error('offline failure');
        return {
            status: 200,
            text: async () => {
                if (scenario === 'body_stall') await untilAborted();
                return '{"ok":true}';
            },
        };
    };

    // Keep Node alive if a regression leaves only an unresolved promise and no request timer.
    const watchdog = originalSetTimeout(() => {
        console.error('Request did not return before the test watchdog expired');
        process.exit(1);
    }, 1000);
    let result;
    try {
        result = await request(args);
    } finally {
        originalClearTimeout(watchdog);
    }
    assert.equal(timers.size, 0, 'Request timer must be cleared even when the request fails');
    if (scenario === 'success') {
        assert.deepEqual(result, {status: 200, body: {ok: true}});
        await new Promise(resolve => originalSetTimeout(resolve, args[4] + 5));
        assert.equal(signal.aborted, false, 'Successful requests must not be aborted later');
    } else {
        assert.equal(result.status, 0);
        assert.match(result.body, scenario === 'error' ? /offline failure/ : /aborted/);
        assert.equal(signal.aborted, scenario !== 'error');
    }
}

main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
