import { verbose, developMode, START, END, charPerLine, uidByteLen } from './constants.js';
import { secretShare } from './crypto.js';
import { errorCheck, showError } from './error_check.js';
import { arrayBufferToString, addLineBreaks } from './common_function.js';


// Send Secure button listener
browser.composeAction.onClicked.addListener(sendEncrypted);


/**
 * Attempts to secret share and send the currently open email
 *
 * @param {*} tab current tab information
 */
async function sendEncrypted(tab) {
	console.info("Attempting to secret share and send an email...");

	// Collect current compose details
	const details = await browser.compose.getComposeDetails(tab.id);

	// Read the From addresses (assumes the format "Sender Name <sender1 sender2 ... senderN>")
	let senders = details.from;
	senders = senders.substring(senders.indexOf('<') + 1, senders.indexOf('>'));	// Read the substring "<...>"
	senders = senders.replaceAll("\"", "");		// Replace " symbols (added by Thunderbird for some reason)
	senders = senders.split(" ");				// Split the string into addresses

	// Generate sender-receiver mapping
	const senderReceiverPairs = getSenderReceiverPairs(senders, details.to);
	const sortedSenders = senderReceiverPairs.senders;
	const sortedReceivers = senderReceiverPairs.receivers;
	const sortedSendersIDs = await attemptAccountIdRetrieval(sortedSenders);

	// Generate email information
	const subject_preId = constructUID(uidByteLen);
	const subject_shares = secretShare(details.subject, sortedSenders.length);
	const messageShares = secretShare(details.plainTextBody, sortedSenders.length);
	const attachmentSharesMap = await getAttachmentSharesAsMap(tab.id, sortedSenders.length);

	// Validate user input
	let inputError = await errorCheck(details, sortedSenders, sortedReceivers, sortedSendersIDs, messageShares);
	if (inputError) {
		console.error(inputError);
		showError(inputError);
		return;
	} else {
		console.info("Error checks were passed successfully.");
	}

	// Remove the original attachment(s)
	await removeAllAttachments(tab.id);

	// Create and send the secret shares
	for (var i = 0; i < messageShares.length; i++) {
		let attachments = [];
		for (const [name, shares] of attachmentSharesMap.entries()) {
			attachments.push({ file: new File([shares[i]], name) });
		}
		let t = i == 0 ? tab : undefined;
		await sendEmail(t, sortedSendersIDs[i], sortedSenders[i], sortedReceivers[i], subject_preId + subject_shares[i], messageShares[i], attachments);
	}
}


/**
 * Secret share the attachments
 *
 * @param {*} tabId id of tab
 * @param {*} n the number of secret shares
 */
async function getAttachmentSharesAsMap(tabId, n) {
	const res = new Map();
	const attachments = await browser.compose.listAttachments(tabId);
	for (const att of attachments) {
		const file = await att.getFile();
		const buf = await file.arrayBuffer();
		const contentAsString = arrayBufferToString(buf);
		const shares = secretShare(contentAsString, n, false, true);
		res.set(att.name, shares);
	}
	return res;
}


/**
 * Removes all attachments from the specified tab window
 *
 * @param {*} tabId id of tab
 */
async function removeAllAttachments(tabId) {
	const attachments = await browser.compose.listAttachments(tabId);
	for (const att of attachments) {
		await browser.compose.removeAttachment(tabId, att.id);
	}
}


/**
 * Queries Thunderbird IDs for the given list of email accounts
 *
 * @param {*} listOfEmails list of email addresses
 * @returns a list of account IDs
 */
async function attemptAccountIdRetrieval(listOfEmails) {
	const accounts = await browser.accounts.list();
	var ids = [];
	for (var i = 0; i < listOfEmails.length; i++) {
		try {
			const acc = accounts.find(a => a.name == listOfEmails[i]);
			const id = acc.identities.find(ai => ai.email == listOfEmails[i]).id;
			ids[i] = id;
		} catch (err) {
			console.error("Could not find a Thunderbird account for " + listOfEmails[i]);
			return null;
		}
	}
	return ids;
}


/**
 * Assigns sender-receiver pairs for the emails so that no server holds all shares at any given point in time
 *
 * @param {*} senders sender email address list
 * @param {*} receivers receiver email address list
 * @returns object of sender and receiver array where sender at index i is matched to receiver at index i
 */
function getSenderReceiverPairs(senders, receivers) {
	let res = { senders: [], receivers: [] };

	// Assume that secure matching possible
	if (senders.length != receivers.length) {

		// Default to maximal distribution (a senders and b receivers -> a*b shares)
		for (let sender of senders) {
			for (let receiver of receivers) {
				res.senders.push(sender);
				res.receivers.push(receiver);
			}
		}

	} else {

		// Attempt a more efficient matching, match the same domains first
		for (let sender of senders) {
			for (let receiver of receivers) {
				// Match if the domain is the same and sender/receiver is not yet matched
				if (sender.split("@")[1] == receiver.split("@")[1] && !Array.from(res.receivers).includes(receiver)) {
					res.senders.push(sender);
					res.receivers.push(receiver);
					break;
				}
			}
		}

		// Match the rest somehow
		for (let sender of senders) {
			if (!Array.from(res.senders).includes(sender)) {
				// Sender not yet matched
				for (let receiver of receivers) {
					if (!Array.from(res.receivers).includes(receiver)) {
						// Receiver not yet matched
						res.senders.push(sender);
						res.receivers.push(receiver);
						break;
					}
				}
			}
		}
	}
	return res;
}


/**
 * Construct and return a random identifier of length uidByteLen as a Base64 string
 *
 * @param {*} uidByteLen length of the UID in bytes
 * @returns UID as a Base64 string
 */
function constructUID(uidByteLen) {
	let uid = new Uint8Array(uidByteLen);
	window.crypto.getRandomValues(uid);
	return btoa(String.fromCharCode.apply(null, uid));
}


/**
 * Sends an email with given settings in this compose tab or a new one
 *
 * @param {*} tab current tab, undefined if to be send in a separate tab
 * @param {*} senderId sender identity
 * @param {*} senderEmail sender email address
 * @param {*} receiver receiver email address
 * @param {*} subject email subject
 * @param {*} body email text
 * @param {*} attachments list of attachments
 */
async function sendEmail(tab, senderId, senderEmail, receiver, subject, body, attachments) {

	console.info("Sending an email...");

	// Add the body shares as content
	let body_content = START + "\n" + addLineBreaks(body, charPerLine) + "\n" + END;

	if (verbose) {
		console.debug("From: " + senderEmail + " (" + senderId + ")");
		console.debug("To: " + receiver);
		console.debug("Subject: " + subject);
		console.debug("Body:\n" + body_content);
	}

	const newDetails = {
		to: receiver,
		from: senderEmail,
		identityId: senderId,
		subject: subject,
		plainTextBody: body_content
	};

	// Send the email in a new tab (except in developMode)
	if (!developMode) {
		const newTab = await browser.compose.beginNew(null, newDetails);
		for (const att of attachments) { await browser.compose.addAttachment(newTab.id, att); }
		browser.compose.sendMessage(newTab.id);
	}

	// Close the current tab automatically (except in developMode)
	if (tab != undefined && !developMode) {
		browser.tabs.remove(tab.id);
	}

	console.info("The email was sent!")
}
