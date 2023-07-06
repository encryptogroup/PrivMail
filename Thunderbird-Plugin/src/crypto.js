import { verbose } from './constants.js';
import { fromBinary, toBinary, base64ToUint8Array, uint8ArrayToBase64 } from "./common_function.js";

/**
 * Returns an array of XOR secret shares (base64) for the given message
 *
 * @param {*} message text (as a string) to be secret shared
 * @param {*} n the number of secret shares
 * @param {*} print enabling debug printing
 * @param {*} convertToBinary converting the message to binary
 */
export function secretShare(message, n, print = true, convertToBinary = false) {
    if (verbose) {
        console.debug("Original string: " + message);
    }

    let res = [];

    // Have to do this for strings including characters bigger than 2 bytes
    if (convertToBinary) {
        message = toBinary(message);
    }

    // Encode message (m) as uint8 Array
    let m = new TextEncoder('utf8').encode(message);

    if (verbose) {
        console.debug("Original string as integers: " + m);
    }

    for (let i = 1; i < n; i++) {
        // Create a random key (k) of same length as the message
        let k = getRandomNumbersArray(m.length);
        res.push(k);
        m = xor(m, k);
    }
    res.push(m);

    // Debug output
    if (print && verbose) {
        for (let i = 0; i < res.length; i++) {
            console.debug("Share (" + (i + 1) + "): " + res[i]);
        }
    }

    let sharesAsBase64 = res.map(x => uint8ArrayToBase64(x));

    // Debug output
    if (print && verbose) {
        for (let i = 0; i < sharesAsBase64.length; i++) {
            console.debug("Share (" + (i + 1) + ") as Base64: " + sharesAsBase64[i]);
        }
    }

    return sharesAsBase64;
}


/**
 * Returns an array filled with random numbers
 *
 * @param {*} length size of the array
 */
function getRandomNumbersArray(length) {
    // randomValuesTreshold is to avoid QuotaExceededError with getRandomValues
    // See: https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
    const randomValuesTreshold = 65536;

    let k = new Uint8Array(length);
    if (length <= randomValuesTreshold) {
        window.crypto.getRandomValues(k);
    } else {
        let tmp = [];
        let remaining = length;
        while (remaining > 0) {
            let j = new Uint8Array(Math.min(randomValuesTreshold, remaining));
            window.crypto.getRandomValues(j);
            tmp.push.apply(tmp, j);
            remaining -= randomValuesTreshold;
        }
        k = tmp;
    }

    return k;
}


/**
 * Performs bitwise XOR operation on two arrays of the same length
 *
 * @param {*} m1 left array
 * @param {*} m2 right array
 * @returns left array XOR right array
 */
function xor(m1, m2) {
    if (m1.length != m2.length) {
        console.error("Cannot XOR different length values!");
        return null;
    }
    for (let i = 0; i < m1.length; i++) {
        m1[i] = m1[i] ^ m2[i];
    }
    return m1;
}


/**
 * Returns XOR result from all given array elements in utf8-text form. Input is assumed to be in base64.
 *
 * @param {*} array array of base64 string to be XORed into plaintext
 * @param {*} convertFromBinary converting the message from binary
 */
export function secretCombine(array, convertFromBinary = false) {
    if (array.length == 0) {
        throw "Empty XOR decipher query";
    }

    if (verbose) {
        for (let i = 0; i < array.length; i++) {
            console.debug("Original share (" + (i + 1) + ") as Base64: " + array[i]);
        }
    }

    // Apply XOR for each array component
    let base = base64ToUint8Array(array[0]);
    for (let i = 1; i < array.length; i++) {
        base = xor(base, base64ToUint8Array(array[i]));
    }

    const res = new TextDecoder('utf8').decode(base);
    return convertFromBinary ? fromBinary(res) : res;
}
