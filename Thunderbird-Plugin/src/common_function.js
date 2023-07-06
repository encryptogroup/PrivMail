import { verbose } from './constants.js';

// Helper functions

export function arrayBufferToString(arrayBuffer) {
	return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
}

export function stringToArrayBuffer(str) {
	let buf = new ArrayBuffer(str.length);
	let bufView = new Uint8Array(buf);
	for (let i = 0; i < str.length; i++) {
		bufView[i] = str.charCodeAt(i);
	}
	return buf;
}

export function toBinary(string) {
	const codeUnits = new Uint16Array(string.length);
	for (let i = 0; i < codeUnits.length; i++) {
		codeUnits[i] = string.charCodeAt(i);
	}
	const charCodes = new Uint8Array(codeUnits.buffer);
	let result = '';
	for (let i = 0; i < charCodes.byteLength; i++) {
		result += String.fromCharCode(charCodes[i]);
	}
	return result;
}

export function fromBinary(binary) {
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	const charCodes = new Uint16Array(bytes.buffer);
	let result = '';
	for (let i = 0; i < charCodes.length; i++) {
		result += String.fromCharCode(charCodes[i]);
	}
	return result;
}

export function downloadFile(url, filename) {
	browser.downloads.download({
		url: url,
		filename: filename,
		conflictAction: 'uniquify'
	});
}

/**
 * Adds line breaks to a long string (for visual purposes)
 *
 * @param {*} string input string
 * @param {*} lineLength the maximum character length per line before the line break
 * @returns the string with the line breaks
 */
export function addLineBreaks(string, lineLength) {
	if (string.length > lineLength) {
		let left_string = string.substring(0, lineLength);
		let right_string = string.substring(lineLength);
		return left_string + "\n" + addLineBreaks(right_string, lineLength);
	}
	return string;
}

/**
 * Converts an array (Uint8Array) to a Base64 string
 *
 * @param {*} array integer array
 * @returns the array as a base64 string
 */
export function uint8ArrayToBase64(array) {
	const base64 = btoa(String.fromCharCode.apply(null, array));
	if (verbose) {
		console.debug("Converted Base64 string: " + base64);
	}
	return base64;
}

/**
 * Converts a Base64 string to an Uint8Array
 *
 * @param {*} base64 string
 * @returns the base64 string as an Uint8Array
 */
export function base64ToUint8Array(base64) {
	const bytes = new Uint8Array(atob(base64).split("").map(x => x.charCodeAt(0)));
	if (verbose) {
		console.debug("Converted integer array: " + bytes);
	}
	return bytes;
}

/**
 * Attempts to make a plaintext string suitable for a HTML page
 *
 * @param {*} text the input plaintext
 * @returns escaped text
 */
export function escapeForHTML(text) {
	// Common characters which must be escaped
	let conversions = {
		'<': 'lt',
		'>': 'gt',
		'"': 'quot',
		'\'': 'apos',
		'&': 'amp',
		'\r': '#10'	};
	let escapedText = text.toString().replace(/[<>"'\r&]/g, function (chr) {
		return '&' + conversions[chr] + ';';
	});

	// Replace line breaks with <br> for the HTML page
    return escapedText.replace(/\n|\r\n|\r/g, '<br/>');
}
