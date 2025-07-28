// _worker.js

// =================================================================================
// SECTION: 配置 (Configuration)
// =================================================================================

/**
 * Docker镜像仓库主机地址 (默认)
 * @type {string}
 */
const DEFAULT_HUB_HOST = 'registry-1.docker.io';

/**
 * Docker认证服务器地址
 * @const {string}
 */
const AUTH_URL = 'https://auth.docker.io';

/**
 * 需要屏蔽的爬虫User-Agent列表
 * @type {string[]}
 */
let 屏蔽爬虫UA = ['netcraft'];

/**
 * CORS预检请求的默认响应配置
 * @type {RequestInit}
 */
const PREFLIGHT_INIT = {
	status: 204,
	headers: new Headers({
		'access-control-allow-origin': '*',
		'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
		'access-control-max-age': '1728000',
	}),
};

// =================================================================================
// SECTION: 主处理程序 (Main Handler)
// =================================================================================

export default {
	/**
	 * Cloudflare Worker的入口函数
	 * @param {Request} request
	 * @param {object} env
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env) {
		// 1. 处理预检请求
		if (request.method === 'OPTIONS') {
			return new Response(null, PREFLIGHT_INIT);
		}

		const url = new URL(request.url);
		const userAgent = request.headers.get('User-Agent')?.toLowerCase() || "null";

		// 从环境变量中加载并合并额外的屏蔽UA
		if (env.UA) {
			屏蔽爬虫UA = 屏蔽爬虫UA.concat(await parseEnvString(env.UA));
		}

		// 2. 检查并拦截被屏蔽的爬虫
		if (屏蔽爬虫UA.length > 0 && 屏蔽爬虫UA.some(ua => userAgent.includes(ua))) {
			return new Response(await nginx(), {
				status: 403,
				headers: { 'Content-Type': 'text/html; charset=UTF-8' },
			});
		}

		// 3. 根据请求确定上游主机地址和行为
		const { upstreamHost, showUiPage } = determineUpstream(url);
		
		// 4. 根据请求类型进行分发
		const isBrowserRequest = userAgent.includes('mozilla');
		const isSearchApiRequest = ['/v1/search', '/v1/repositories'].some(path => url.pathname.includes(path));

		if (isBrowserRequest || isSearchApiRequest) {
			return handleUiRequest(request, url, env, showUiPage);
		} else {
			return handleApiRequest(request, url, upstreamHost);
		}
	}
};

// =================================================================================
// SECTION: 核心逻辑函数 (Core Logic Functions)
// =================================================================================

/**
 * 处理面向浏览器的UI请求和搜索API请求。
 * @param {Request} request
 * @param {URL} url
 * @param {object} env
 * @param {boolean} showUiPage
 * @returns {Promise<Response>}
 */
async function handleUiRequest(request, url, env, showUiPage) {
	// 根路径处理
	if (url.pathname === '/') {
		if (env.URL302) return Response.redirect(env.URL302, 302);
		if (env.URL) {
			if (env.URL.toLowerCase() === 'nginx') {
				return new Response(await nginx(), { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
			}
			return fetch(new Request(env.URL, request));
		}
		// 默认显示美化的搜索界面（如果路由配置需要）
		if (showUiPage) {
			return new Response(await searchInterface(), { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		}
	}

	// 特殊路径代理
	if (url.pathname.startsWith('/v1/')) {
		// v1 API (如搜索) 代理到 index.docker.io
		url.hostname = 'index.docker.io';
	} else if (showUiPage) {
		// 其他UI相关路径（如/search页面）代理到 hub.docker.com
		url.hostname = 'hub.docker.com';
	}

	// 规范化官方库的搜索 'library/nginx' -> 'nginx'
	const query = url.searchParams.get('q');
	if (query?.startsWith('library/')) {
		url.searchParams.set('q', query.substring(8));
	}
	
	return fetch(new Request(url, request));
}

/**
 * 处理所有Docker API请求。
 * @param {Request} request
 * @param {URL} url
 * @param {string} upstreamHost
 * @returns {Promise<Response>}
 */
async function handleApiRequest(request, url, upstreamHost) {
	// 1. 代理Docker认证Token请求
	if (url.pathname.includes('/token')) {
		const tokenUrl = AUTH_URL + url.pathname + url.search;
		const tokenRequest = new Request(tokenUrl, request);
		tokenRequest.headers.set('Host', 'auth.docker.io');
		return fetch(tokenRequest);
	}

	// 2. 自动为Docker Hub官方镜像添加 'library/' 前缀
	if (upstreamHost === DEFAULT_HUB_HOST && /^\/v2\/[^/]+\/[^/]+\/[^/]+$/.test(url.pathname) && !/^\/v2\/library/.test(url.pathname)) {
		url.pathname = `/v2/library${url.pathname.substring(3)}`;
		console.log(`Modified URL for library image: ${url.pathname}`);
	}
	
	// 3. 检查是否需要预先获取Token (适用于 manifests, blobs, tags)
	const needsToken = /^\/v2\/.*?\/(manifests|blobs|tags)\/.*/.test(url.pathname);
	let authToken = null;

	if (needsToken) {
		authToken = await fetchToken(url, request.headers);
		if (!authToken) {
			// 如果无法获取Token，返回认证质询
			const repo = url.pathname.match(/^\/v2\/(.*?)\/(manifests|blobs|tags)/)?.[1];
			const wwwAuthHeader = `Bearer realm="${AUTH_URL}/token",service="registry.docker.io",scope="repository:${repo}:pull"`;
			return new Response('Unauthorized', {
				status: 401,
				headers: { 'Www-Authenticate': wwwAuthHeader }
			});
		}
	}

	// 4. 构造并发送代理请求
	return proxyRequestAndProcessResponse(request, url, upstreamHost, authToken);
}


/**
 * 为需要认证的API请求获取Bearer Token。
 * @param {URL} url - 请求的URL，用于提取仓库名。
 * @param {Headers} headers - 原始请求头。
 * @returns {Promise<string|null>} 成功则返回Token，失败返回null。
 */
async function fetchToken(url, headers) {
	const repoMatch = url.pathname.match(/^\/v2\/(.*?)\/(manifests|blobs|tags)/);
	const repo = repoMatch ? repoMatch[1] : null;
	if (!repo) return null;

	const tokenUrl = `${AUTH_URL}/token?service=registry.docker.io&scope=repository:${repo}:pull`;
	
	const tokenResponse = await fetch(tokenUrl, {
		headers: {
			'User-Agent': headers.get("User-Agent"),
			'Accept': headers.get("Accept"),
			'Accept-Language': headers.get("Accept-Language"),
			'Accept-Encoding': headers.get("Accept-Encoding"),
		}
	});

	if (!tokenResponse.ok) return null;

	const tokenData = await tokenResponse.json();
	return tokenData.token || null;
}

/**
 * 构造代理请求、发送并处理响应。
 * @param {Request} request - 原始请求。
 * @param {URL} url - 目标URL。
 * @param {string} upstreamHost - 上游主机。
 * @param {string|null} authToken - 可选的Bearer Token。
 * @returns {Promise<Response>}
 */
async function proxyRequestAndProcessResponse(request, url, upstreamHost, authToken) {
	url.hostname = upstreamHost;
	const proxyReq = new Request(url, request);
	proxyReq.headers.set('Host', upstreamHost);

	if (authToken) {
		proxyReq.headers.set('Authorization', `Bearer ${authToken}`);
	}

	// 发起请求
	const upstreamResponse = await fetch(proxyReq, { cacheTtl: 3600 });
	
	// 处理重定向
	const location = upstreamResponse.headers.get('Location');
	if (location) {
		console.info(`Handling redirect to: ${location}`);
		return handleRedirect(request, location, upstreamHost);
	}

	// 修改响应头
	const responseHeaders = new Headers(upstreamResponse.headers);
	const workersHost = new URL(request.url).hostname;
	const wwwAuthHeader = responseHeaders.get("Www-Authenticate");
	if (wwwAuthHeader) {
		responseHeaders.set("Www-Authenticate", wwwAuthHeader.replace(AUTH_URL, `https://${workersHost}`));
	}
	
	responseHeaders.set('access-control-allow-origin', '*');
	responseHeaders.set('access-control-expose-headers', '*');

	return new Response(upstreamResponse.body, {
		status: upstreamResponse.status,
		headers: responseHeaders,
	});
}

/**
 * 处理上游返回的HTTP重定向。
 * @param {Request} req - 原始请求对象。
 * @param {string} location - 'Location'头指定的重定向URL。
 * @param {string} baseHost - 当前请求的上游主机地址。
 * @returns {Promise<Response>}
 */
function handleRedirect(req, location, baseHost) {
	const urlObj = new URL(location, `https://${baseHost}`);
	const reqHeaders = new Headers(req.headers);

	// S3返回的预签名URL通常包含认证信息，如果再携带Authorization头会导致签名验证失败。
	reqHeaders.delete("Authorization");

	const reqInit = {
		method: req.method,
		headers: reqHeaders,
		redirect: 'follow',
		body: req.body
	};

	return proxy(urlObj, reqInit);
}

/**
 * 代理请求到指定的URL (主要用于处理重定向后的请求)。
 * @param {URL} urlObj - 目标URL对象。
 * @param {RequestInit} reqInit - 请求的初始化配置。
 * @returns {Promise<Response>}
 */
async function proxy(urlObj, reqInit) {
	const res = await fetch(urlObj.href, reqInit);
	const resHeaders = new Headers(res.headers);

	// 设置CORS相关的响应头
	resHeaders.set('access-control-expose-headers', '*');
	resHeaders.set('access-control-allow-origin', '*');
	resHeaders.set('Cache-Control', 'max-age=1500');

	// 删除可能引起安全问题的头
	resHeaders.delete('content-security-policy');
	resHeaders.delete('content-security-policy-report-only');
	resHeaders.delete('clear-site-data');

	return new Response(res.body, {
		status: res.status,
		headers: resHeaders,
	});
}


/**
 * 根据请求URL确定上游主机地址。
 * @param {URL} url - 请求的URL对象。
 * @returns {{upstreamHost: string, showUiPage: boolean}} 返回上游主机地址和是否显示UI页面的标志。
 */
function determineUpstream(url) {
	const ns = url.searchParams.get('ns');
	if (ns) {
		const upstream = (ns === 'docker.io') ? DEFAULT_HUB_HOST : ns;
		return { upstreamHost: upstream, showUiPage: false };
	}

	const hostname = url.searchParams.get('hubhost') || url.hostname;
	const hostPrefix = hostname.split('.')[0];
	
	const [host, isDefaultHub] = routeByHosts(hostPrefix);
	
	// 如果路由结果是默认的Docker Hub，且没有`hubhost`参数，则显示UI页面
	const showUiPage = isDefaultHub && !url.searchParams.has('hubhost');

	return { upstreamHost: host, showUiPage };
}

/**
 * 根据主机名前缀选择上游地址。
 * @param {string} hostPrefix - 主机名的第一部分。
 * @returns {[string, boolean]} 返回一个元组：[上游地址, 是否为默认Docker Hub]。
 */
function routeByHosts(hostPrefix) {
	const routes = {
		"quay": "quay.io", "gcr": "gcr.io", "k8s-gcr": "k8s.gcr.io",
		"k8s": "registry.k8s.io", "ghcr": "ghcr.io", "cloudsmith": "docker.cloudsmith.io",
		"nvcr": "nvcr.io", "test": DEFAULT_HUB_HOST,
	};
	if (hostPrefix in routes) {
		return [routes[hostPrefix], false];
	}
	return [DEFAULT_HUB_HOST, true];
}


// =================================================================================
// SECTION: HTML内容生成器 (HTML Content Generators)
// =================================================================================

/**
 * 生成一个仿Nginx欢迎页面的HTML。
 * @returns {Promise<string>}
 */
async function nginx() {
	return `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>`;
}

/**
 * 生成一个美化的Docker Hub镜像搜索界面的HTML。
 * @returns {Promise<string>}
 */
async function searchInterface() {
	return `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Docker Hub 镜像搜索</title>
		<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
		<style>
		:root{--github-color:rgb(27,86,198);--github-bg-color:#ffffff;--primary-color:#0066ff;--primary-dark:#0052cc;--gradient-start:#1a90ff;--gradient-end:#003eb3;--text-color:#ffffff;--shadow-color:rgba(0,0,0,0.1);--transition-time:0.3s}
		*{box-sizing:border-box;margin:0;padding:0}
		body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;display:flex;flex-direction:column;justify-content:center;align-items:center;min-height:100vh;margin:0;background:linear-gradient(135deg,var(--gradient-start) 0%,var(--gradient-end) 100%);padding:20px;color:var(--text-color);overflow-x:hidden}
		.container{text-align:center;width:100%;max-width:800px;padding:20px;margin:0 auto;display:flex;flex-direction:column;justify-content:center;min-height:60vh;animation:fadeIn .8s ease-out}
		@keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
		.github-corner{position:fixed;top:0;right:0;z-index:999;transition:transform var(--transition-time) ease}
		.github-corner:hover{transform:scale(1.08)}
		.github-corner svg{fill:var(--github-bg-color);color:var(--github-color);position:absolute;top:0;border:0;right:0;width:80px;height:80px;filter:drop-shadow(0 2px 5px rgba(0,0,0,.2))}
		.logo{margin-bottom:20px;transition:transform var(--transition-time) ease;animation:float 6s ease-in-out infinite}
		@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
		.logo:hover{transform:scale(1.08) rotate(5deg)}
		.logo svg{filter:drop-shadow(0 5px 15px rgba(0,0,0,.2))}
		.title{color:var(--text-color);font-size:2.3em;margin-bottom:10px;text-shadow:0 2px 10px rgba(0,0,0,.2);font-weight:700;letter-spacing:-.5px;animation:slideInFromTop .5s ease-out .2s both}
		@keyframes slideInFromTop{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
		.subtitle{color:rgba(255,255,255,.9);font-size:1.1em;margin-bottom:25px;max-width:600px;margin-left:auto;margin-right:auto;line-height:1.4;animation:slideInFromTop .5s ease-out .4s both}
		.search-container{display:flex;align-items:stretch;width:100%;max-width:600px;margin:0 auto;height:55px;position:relative;animation:slideInFromBottom .5s ease-out .6s both;box-shadow:0 10px 25px rgba(0,0,0,.15);border-radius:12px;overflow:hidden}
		@keyframes slideInFromBottom{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
		#search-input{flex:1;padding:0 20px;font-size:16px;border:none;outline:none;transition:all var(--transition-time) ease;height:100%}
		#search-input:focus{padding-left:25px}
		#search-button{width:60px;background-color:var(--primary-color);border:none;cursor:pointer;transition:all var(--transition-time) ease;height:100%;display:flex;align-items:center;justify-content:center;position:relative}
		#search-button svg{transition:transform .3s ease;stroke:white}
		#search-button:hover{background-color:var(--primary-dark)}
		#search-button:hover svg{transform:translateX(2px)}
		#search-button:active svg{transform:translateX(4px)}
		.tips{color:rgba(255,255,255,.8);margin-top:20px;font-size:.9em;animation:fadeIn .5s ease-out .8s both;transition:transform var(--transition-time) ease}
		.tips:hover{transform:translateY(-2px)}
		@media (max-width:768px){.container{padding:20px 15px;min-height:60vh}.title{font-size:2em}.subtitle{font-size:1em;margin-bottom:20px}.search-container{height:50px}}
		@media (max-width:480px){.container{padding:15px 10px;min-height:60vh}.github-corner svg{width:60px;height:60px}.search-container{height:45px}#search-input{padding:0 15px}#search-button{width:50px}#search-button svg{width:18px;height:18px}.title{font-size:1.7em;margin-bottom:8px}.subtitle{font-size:.95em;margin-bottom:18px}}
		</style>
	</head>
	<body>
		<a href="https://github.com/cmliu/CF-Workers-docker.io" target="_blank" class="github-corner" aria-label="View source on Github"><svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin:130px 106px" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg></a>
		<div class="container">
			<div class="logo"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 18" fill="#ffffff" width="110" height="85"><path d="M23.763 6.886c-.065-.053-.673-.512-1.954-.512-.32 0-.659.03-1.01.087-.248-1.703-1.651-2.533-1.716-2.57l-.345-.2-.227.328a4.596 4.596 0 0 0-.611 1.433c-.23.972-.09 1.884.403 2.666-.596.331-1.546.418-1.744.42H.752a.753.753 0 0 0-.75.749c-.007 1.456.233 2.864.692 4.07.545 1.43 1.355 2.483 2.409 3.13 1.181.725 3.104 1.14 5.276 1.14 1.016 0 2.03-.092 2.93-.266 1.417-.273 2.705-.742 3.826-1.391a10.497 10.497 0 0 0 2.61-2.14c1.252-1.42 1.998-3.005 2.553-4.408.075.003.148.005.221.005 1.371 0 2.215-.55 2.68-1.01.505-.5.685-.998.704-1.053L24 7.076l-.237-.19Z"/><path d="M2.216 8.075h2.119a.186.186 0 0 0 .185-.186V6a.186.186 0 0 0-.185-.186H2.216A.186.186 0 0 0 2.031 6v1.89c0 .103.083.186.185.186Zm2.92 0h2.118a.185.185 0 0 0 .185-.186V6a.185.185 0 0 0-.185-.186H5.136A.185.185 0 0 0 4.95 6v1.89c0 .103.083.186.186.186Zm2.964 0h2.118a.186.186 0 0 0 .185-.186V6a.186.186 0 0 0-.185-.186H8.1A.185.185 0 0 0 7.914 6v1.89c0 .103.083.186.186.186Zm2.928 0h2.119a.185.185 0 0 0 .185-.186V6a.185.185 0 0 0-.185-.186h-2.119a.186.186 0 0 0-.185.186v1.89c0 .103.083.186.185.186Zm-5.892-2.72h2.118a.185.185 0 0 0 .185-.186V3.28a.186.186 0 0 0-.185-.186H5.136a.186.186 0 0 0-.186.186v1.89c0 .103.083.186.186.186Zm2.964 0h2.118a.186.186 0 0 0 .185-.186V3.28a.186.186 0 0 0-.185-.186H8.1a.186.186 0 0 0-.186.186v1.89c0 .103.083.186.186.186Zm2.928 0h2.119a.185.185 0 0 0 .185-.186V3.28a.186.186 0 0 0-.185-.186h-2.119a.186.186 0 0 0-.185.186v1.89c0 .103.083.186.185.186Zm0-2.72h2.119a.186.186 0 0 0 .185-.186V.56a.185.185 0 0 0-.185-.186h-2.119a.186.186 0 0 0-.185.186v1.89c0 .103.083.186.185.186Zm2.955 5.44h2.118a.185.185 0 0 0 .186-.186V6a.185.185 0 0 0-.186-.186h-2.118a.185.185 0 0 0-.185.186v1.89c0 .103.083.186.185.186Z"/></svg></div>
			<h1 class="title">Docker Hub 镜像搜索</h1>
			<p class="subtitle">快速查找、下载和部署 Docker 容器镜像</p>
			<div class="search-container">
				<input type="text" id="search-input" placeholder="输入关键词搜索镜像，如: nginx, mysql, redis...">
				<button id="search-button" title="搜索"><svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M13 5l7 7-7 7M5 5l7 7-7 7" stroke-linecap="round" stroke-linejoin="round"></path></svg></button>
			</div>
			<p class="tips">基于 Cloudflare Workers / Pages 构建，利用全球边缘网络实现毫秒级响应。</p>
		</div>
		<script>
		function performSearch(){const e=document.getElementById("search-input").value;e&&(window.location.href="/search?q="+encodeURIComponent(e))}
		document.getElementById("search-button").addEventListener("click",performSearch);
		document.getElementById("search-input").addEventListener("keypress",function(e){"Enter"===e.key&&performSearch()});
		window.addEventListener("load",function(){document.getElementById("search-input").focus()});
		</script>
	</body>
	</html>
	`;
}

// =================================================================================
// SECTION: 工具函数 (Utility Functions)
// =================================================================================

/**
 * 将环境变量中以多种分隔符分隔的字符串解析为数组。
 * @param {string} envString - 从环境变量读取的字符串。
 * @returns {Promise<string[]>} 解析后的字符串数组。
 */
async function parseEnvString(envString) {
	if (!envString) return [];
	let text = envString.replace(/[	 |"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (text.startsWith(',')) text = text.slice(1);
	if (text.endsWith(',')) text = text.slice(0, -1);
	return text.split(',').filter(item => item); // 过滤掉空字符串
}
