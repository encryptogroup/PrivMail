import { START, END, uidByteLen, verbose } from './constants.js';
import { secretCombine } from './crypto.js';
import { stringToArrayBuffer, downloadFile, escapeForHTML } from './common_function.js';
import { showError } from './error_check.js';


// Combine button listener
browser.messageDisplayAction.onClicked.addListener(decryptMessage);


/**
 * Attempts to combine the currently selected email with secret shares from all inboxes
 *
 * @param {*} tab current tab information
 */
async function decryptMessage(tab) {
    console.info("Attempting to combine an email with secret shares from all inboxes...");

    // Get secret shares
    const currentTabMessageHeader = await browser.messageDisplay.getDisplayedMessage(tab.id);
    const sharedId = getSharedIdFromSubject(currentTabMessageHeader.subject);
    const messages = await getMessageListFromSharedSecretId(sharedId);
    const fullMessages = await getFullMessages(messages);
    const fullMessageBodies = getFullMessageBodiesFromFullMessages(fullMessages);
    const fullMessageSubjects = Array.from(fullMessages, fm => getSecretFromSubject(fm.headers.subject[0]));
    const attachmentsSharesMap = await getAttachmentSharesAsMap(messages);

    // Combine the shares
    const subject_plaintext = secretCombine(fullMessageSubjects);
    const body_plaintext = secretCombine(fullMessageBodies);
    const combined_attachments = getCombinedAttachmentsAsFiles(attachmentsSharesMap);

    if (verbose) {
        console.debug("Subject combined: " + subject_plaintext);
        console.debug("Body combined: " + body_plaintext);
    }

    displayDecrypted(subject_plaintext, body_plaintext, combined_attachments);
    console.info("The email was combined!")
}


/**
 * Search for the actual text body data, which might vary depending on the email content-type
 *
 * @param {*} fullMessages fullMessages from getFullMessages function
 * @returns array of strings
 */
function getFullMessageBodiesFromFullMessages(fullMessages) {
    let res = [];
    for (const fm of fullMessages) {
        let body = "";
        if (fm.parts[0].hasOwnProperty('body')) {
            body = fm.parts[0].body;
        } else {
            body = fm.parts[0].parts[0].body;
        }
        let bodyLines = body.split("\n");
        res.push(bodyLines.slice(bodyLines.indexOf(START) + 1, bodyLines.indexOf(END)).join(''));
    }
    return res;
}


/**
 * Queries for mails in the inbox that have a subject that contains the specified identifier
 *
 * @param {*} sharedId identifier extracted as number from the subject field
 * @returns array of mails
 */
async function getMessageListFromSharedSecretId(sharedId) {
    let queryInfo = { 'subject': sharedId };
    const parts = (await messenger.messages.query(queryInfo)).messages.filter(message => message.folder.type == "inbox");
    return parts;
}


/**
 * Retrieves the email content from email specifiers
 *
 * @param {*} messages array of email specifiers
 * @returns array of the respective emails content
 */
async function getFullMessages(messages) {
    let res = [];
    for (let i = 0; i < messages.length; i++) {
        res.push(await messenger.messages.getFull(messages[i].id));
    }
    return res;
}


/**
 * Returns all the attachments of a message as a map, e.g., {img1.jpg : [share1, share2,...]}
 *
 * @param {*} messages array of email specifiers
 * @returns map of names and secret shares
 */
async function getAttachmentSharesAsMap(messages) {
    const res = new Map();
    for (let i = 0; i < messages.length; i++) {
        let attachments = await browser.messages.listAttachments(messages[i].id);
        for (let att of attachments) {
            let file = await browser.messages.getAttachmentFile(
                messages[i].id,
                att.partName
            );
            let content = await file.text();
            let name = file.name;
            let shares = res.get(name);
            if (shares == undefined) {
                res.set(name, [content]);
            } else {
                shares.push(content);
                res.set(name, shares);
            }
        }
    }
    return res;
}


/**
 * Combine the map of attachment shares
 *
 * @param {*} attachmentSharesMap map of attachment shares
 * @returns list of files
 */
function getCombinedAttachmentsAsFiles(attachmentSharesMap) {
    let res = [];
    for (const [name, shares] of attachmentSharesMap.entries()) {
        const combined = secretCombine(shares, true);
        const buffer = stringToArrayBuffer(combined);
        res.push(new File([buffer], name));
    }
    return res;
}


// Listen to the tabs onRemoved event
browser.tabs.onRemoved.addListener(tabsOnRemovedListener);
function tabsOnRemovedListener(tabId) {
    // If the "read_combined" tab is closed, reset the readTabID to zero, s.t. the displayDecrypted() function does not try to remove an already closed tab.
    if (tabId == readTabID) {
        readTabID = 0;
    }
}


var readTabID = 0; // Holds the tab ID of the "read_combined" tab (should be 0 if the tab is not open)
/**
 * Display the combined email in a new Thunderbird tab and download combined the attachments
 *
 * @param {*} subject plain subject
 * @param {*} message plain message
 * @param {*} attachments list of attachments
 */
async function displayDecrypted(subject, message, attachments) {
    for (const att of attachments) {
        const url = URL.createObjectURL(att);
        downloadFile(url, att.name);
    }

    if (readTabID != 0) {
        browser.tabs.remove(readTabID); // Remove the (old) open tab
    }

    // Try to make the message suitable for the HTML page
    message = escapeForHTML(message);

    if (verbose) {
        console.debug("Combined subject: " + subject);
        console.debug("Combined HTML message: " + message);
    }

    await browser.tabs.create({ url: './src/read_combined.html' })
        .then((response) => {
            browser.tabs.executeScript(response.id, {
                code: `document.getElementById('subject').innerHTML = '${subject}';
                       document.getElementById('message').innerHTML = '${message}';`
            }).then((resp) => { console.info("Combined email available in a new tab."); },
                (resp) => {
                    console.error("Failed to put the combined email in a new tab: " + resp);
                    console.log("The email body: " + message);
                    showError("Could not show the email in a new tab. Check the logs to see the email.");
                });
            readTabID = response.id;    // Store the current tab ID so that it can be removed the next time
        });
}


/**
 * Retrieves the ID from the email subject
 *
 * @param {*} subject the subject as a string
 * @returns ID
 */
function getSharedIdFromSubject(subject) {
    const uidStringLen = 4 * Math.ceil(uidByteLen / 3);
    return subject.substring(0, uidStringLen);
}


/**
 * Retrieves the secret shared part of the email subject
 *
 * @param {*} subject the subject as a string
 * @returns secret shared part of the email subject
 */
function getSecretFromSubject(subject) {
    const uidStringLen = 4 * Math.ceil(uidByteLen / 3);
    return subject.substring(uidStringLen);
}
