import jwt from '@tsndr/cloudflare-worker-jwt';
import userJwt1 from "./budi.js";

export default {
	async fetch(request, env, ctx) {

		//let userJwt = request.headers.get("Cf-Access-Jwt-Assertion");
		//console.log(userJwt.name);
		let userJwt = userJwt1.name;

		const { payload } = jwt.decode(userJwt);
		const dateTimestamp  = (new Date(payload.iat * 1000)).toISOString();
		const url = "https://restcountries.com/v3.1/alpha/" + payload.country;
		console.log('14');
    const response = await fetch(url, {
			headers: {
        "content-type": "application/json;charset=UTF-8",
      },
		});
		console.log('20');
		const namanya = await response.json();
		const countryName = namanya[0].name.common;
		console.log("countryName: " + countryName);
		const strCountry = "<a href=\"/secure/" + payload.country + "\" class=\"text-blue-400 hover:underline\">"+ countryName +"</a>";

		var html = "<!DOCTYPE html>";
		html += "<head>";
		html += "<script src=\"https://cdn.tailwindcss.com\"></script>";
		html += "</head>";
		html += "<body>";
		html += "<div class=\"h-screen flex items-center justify-center text-3xl text-gray-500\">";
		html += `<p><span class=\"font-bold\">${payload.email}</span> authenticated at <span class=\"font-bold\">${dateTimestamp}</span> from <span class=\"font-bold\">${strCountry}</span>`;
		html += "<br /><br />Go back <a href=\"/\" class=\"text-blue-400 hover:underline\">home</a>";
		html += "</p></div>";
		html += "</body>";

		return new Response(html, {
      headers: {
        "content-type": "text/html;charset=UTF-8"
			}
		})
	},
};

