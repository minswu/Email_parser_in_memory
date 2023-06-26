rule email_parser
{
    strings:
        $s1=/\{\"Message\":\{\"ID\"\:.+?\"Sender\"\:.+?\"ToList\"\:.+?END PGP MESSAGE.+?\}\}/
        $s2=/\{\"_area\".+\"_format\".+\}\]\}/
        $s3=/Content-Disposition:.+name=\"smtoken\"[\w\W\s]{2,}Content-Disposition:.+name=\"querystring\"/
        $s4=/Content-Disposition:.+name=\"_csrf\"[\w\W\s]{2,}name=\"files\".+\s{2}Content-Type.+/
        $s5=/Content-Disposition:.+name=\"smtoken\"[\w\W\s]{2,}name=\"send_button_count\"/
        $s6=/Content-Disposition:.+name=\"smtoken\"[\w\W\s]{2,}name=\"attachfile\".+\s{2}Content-Type.+/
        $s7=/Content-Disposition:.+name=\"susiNonce\"[\w\W\s]{2,}name=\"new_filename\"; filename=\".+\s{2}Content-Type:.+/
        $s8=/7\|0\|\d+?\|https:\/\/mailfence\.com\/flatx\/co\/\|[\w\W\s]+?\|TargetAccount\|MessageTimestamp\|\d+?\|/
        $s9=/Content-Disposition:.+name=\"senderName\"[\w\W\s]{2,}name=\"seqNums\"/
        $s10=/\{\"__type\":\"UpdateItemJsonRequest:#Exchange\".+?\"Body\":.+?\"PropertyUri:#Exchange\".+?\"IsReadReceiptRequested\":.+?\"DistinguishedPropertySetId\".+?\}\]\}\}\]/
        $s11=/\{\"requests\":\[\{\"id\":\"SaveMessage\".+?\"message\":.+?\"filters\".+?\"responseType\":.+?\}/
        $s12=/\{\"result\":\{\"responses\":\[\{\"id\":\"SaveMessage\".+?\"response\":.+?\{\"id\":\"SendMessage\".+?\"error\":.+?\}/
        $s13=/\{"composerId\":.+?\"from\":.+?\"subject\":.+?"optionalData\":.+?\}\}/
        $s14=/\[.+,\[\"thread-a:r.+\[\[\"msg-a:r.+\],.+\].+\|#msg-a:r.+\],.+\]/
        $s15=/senderName=.+senderAddress=.+body=.+sendSeparately=.+seqNums=.+u=.+/

    condition:
        $s1 or $s2 or $s3 or $s4 or $s5 or $s6 or $s7 or $s8 or $s9 or $s10 or $s11 or $s12 or $s13 or $s14 or $s15
}