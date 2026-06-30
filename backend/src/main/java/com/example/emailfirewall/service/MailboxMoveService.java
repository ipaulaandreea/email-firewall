//package com.example.emailfirewall.service;
//
//import jakarta.mail.*;
//import jakarta.mail.Flags;
//import jakarta.mail.UIDFolder;
//import org.springframework.stereotype.Service;
//
//@Service
//public class MailboxMoveService {
//
//    public void moveByUid(Store store, long uid, String sourceFolderName, String targetFolderName)
//            throws MessagingException {
//
//        Folder sourceFolder = store.getFolder(sourceFolderName);
//        sourceFolder.open(Folder.READ_WRITE);
//
//        Folder targetFolder = store.getFolder(targetFolderName);
//
//        if (!targetFolder.exists()) {
//            targetFolder.create(Folder.HOLDS_MESSAGES);
//        }
//
//        UIDFolder uidFolder = (UIDFolder) sourceFolder;
//        Message message = uidFolder.getMessageByUID(uid);
//
//        if (message == null) {
//            sourceFolder.close(false);
//            throw new MessagingException("Message not found by UID: " + uid);
//        }
//
//        sourceFolder.copyMessages(new Message[]{message}, targetFolder);
//
//        message.setFlag(Flags.Flag.DELETED, true);
//
//        sourceFolder.close(true);
//    }
//}