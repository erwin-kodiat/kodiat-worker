/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */
import jwt from '@tsndr/cloudflare-worker-jwt';

export default {
	async fetch(request, env, ctx) {
		var txt = 'Hello World!' + "\n";
		// console.log(request.headers);
		// console.log("Kok sepi?");

		// let userEmail = request.headers.get("Cf-Access-Authenticated-User-Email") || '_development';
    // txt += userEmail + "\n";

		let userJwt = request.headers.get("Cf-Access-Jwt-Assertion") || '_production';
    // txt += userJwt + "\n";;

		const { payload } = jwt.decode(userJwt);
		txt += "Email: " + payload.email + "\n";
		txt += "Timestamp: " + payload.iat + "\n";
		txt += "Country: " + payload.country + "\n";

		// console.log(payload.aud);

		return new Response(txt);
	},
};

