import { strictSecurity } from './constants.js';

/**
 * Various checks before sending the email
 * @returns Error message as a string or `undefined`
 */
export async function errorCheck(details, senders, receivers, senderIDs, sharedMessage) {

	if (details.bcc.length > 0) {
		return "BCC is not supported!";
	} else if (details.cc.length > 0) {
		return "CC is not supported!";
	} else if (details.replyTo.length > 0) {
		return "ReplyTo is not supported!";
	} else if (details.followupTo.length > 0) {
		return "FollowUpTo is not supported!";
	} else if (senders.length <= 1) {
		return "Sender information is missing!";
	} else if (receivers.length <= 1) {
		return "Receiver information is missing!";
	} else if (senderIDs == null || senderIDs.length != senders.length) {
		return "Couldn't get sender IDs. Are all sender addresses related to a mail account in Thunderbird?";
	} else if (senders.length != sharedMessage.length) {
		return "The number of outgoing mails and shares do not match!";
	}

	// Validate the email addresses
	for (let senderMail of senders) {
		if (!senderMail.match(/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/)) {
			return "Invalid sender address '" + senderMail + "'! The addresses should be specified as:  <sender1 sender2 ...>.";
		}
	}

	/* In order to preserve privacy, we must assume that the email servers don't collude. Because of this,
	   we want to assure that the domains on each end are not all the same. */

	let warnings = []
	if (!strictSecurity) {
		warnings.push("Strict security mode is not enabled and some privacy checks were ignored!");
	}

	// The sender domains shouldn't be all the same
	let foundDifferingSender = false;
	let senderMail_a = senders[0];
	for (let senderMail_b of senders) {
		if (senderMail_a.split("@")[1] != senderMail_b.split("@")[1]) {
			foundDifferingSender = true;
			break;
		}
	}
	if (!foundDifferingSender) {
		warnings.push("The outgoing mail server can reconstruct the email! Include at least one sender address with a different domain.");
	}

	// The receiver domains shouldn't be all the same
	let foundDifferingReceiver = false;
	let receiverMail_a = details.to[0];
	for (let receiverMail_b of details.to) {
		if (receiverMail_a.split("@")[1] != receiverMail_b.split("@")[1]) {
			foundDifferingReceiver = true;
			break;
		}
	}
	if (!foundDifferingReceiver) {
		warnings.push("The incoming mail server can reconstruct the email! Include at least one receiver address with a different domain.");
	}

	if (warnings.length) {
		if (strictSecurity) {
			return warnings[0];	// Use the first warning message as the error
		} else {
			if (warnings.length > 1) {
				for (let warning of warnings) {
					console.warn(warning);
				}
				showWarning(warnings);
			}
		}
	}

	// All checks were passed!
	return undefined;
}


var errorTabID = 0; // Holds the tab ID of the "error" tab (should be 0 if the tab is not open)
/**
 * Display an error message in a new Thunderbird tab
 *
 * @param {*} message error message as a string
 */
export async function showError(message) {
	if (errorTabID != 0) {
		browser.tabs.remove(errorTabID);	// Remove the (old) open tab
	}

	await browser.tabs.create({ url: './src/error.html' })
		.then((response) => {
			browser.tabs.executeScript(response.id, {
				code: `document.getElementById('message').innerHTML = '${message}';`
			});
			errorTabID = response.id;		// Store the current tab ID so that it can be removed the next time
		});
}


var warningTabID = 0; // Holds the tab ID of the "warning" tab (should be 0 if the tab is not open)
/**
 * Display a warning message(s) in a new Thunderbird tab
 *
 * @param {*} messages warning messages in an array
 */
export async function showWarning(messages) {
	if (warningTabID) {
		browser.tabs.remove(warningTabID);	// Remove the (old) open tab
	}

	await browser.tabs.create({ url: './src/warning.html' })
		.then((response) => {
			for (let message of messages) {
				browser.tabs.executeScript(response.id, {
					code: `var list = document.createElement('li');
						   list.appendChild(document.createTextNode('${message}'));
						   document.getElementById('warnings').appendChild(list);
						   undefined;`
				});
			}
			warningTabID = response.id;		// Store the current tab ID so that it can be removed the next time
		});
}
