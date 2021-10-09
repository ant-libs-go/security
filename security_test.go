/* ######################################################################
# Author: (zfly1207@126.com)
# Created Time: 2020-08-05 10:33:40
# File Name: security_test.go
# Description:
####################################################################### */

package security

import (
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestEncode(t *testing.T) {
	key := "8dssword99.2020%"
	rawStr := "abcdefg"

	mgr := New(key)
	encStr := mgr.Encode(rawStr)
	decStr, err := mgr.Decode(encStr)
	decStr = strings.Trim(decStr, "\t")

	Convey("TestEncode", t, func() {
		Convey("TestDecode err should return nil", func() {
			So(err, ShouldBeNil)
		})
		Convey("TestDecode result should equal rawStr", func() {
			So(decStr, ShouldEqual, rawStr)
		})
	})
}

/*
func main() {

    tracker := &pb_union.TrackerInfo{
        TraceId: "traceidtraceidtraceid",
        ReqTs:   1234567890,
        AppId:   10002,
        //SlotId:      10003,
        ChannelId:   1,
        ChnSlotId:   "slotid",
        AdType:      3,
        AdStyleType: 10004,
        //Ip:          "127.0.0.1",
        //Ext:         map[string]string{},
    }
    b, err := proto.Marshal(tracker)
    if err != nil {
        fmt.Println("err1: ", err)
    }
    tr := security.New().Encode("x2d87b5c6s%s$c.A", string(b))
    fmt.Println(tr)
    fmt.Println(b)
    ioutil.WriteFile("/tmp/test/a", b, 0666)

    // ---

    trace, err := security.New().Decode("x2d87b5c6s%s$c.A", tr)
    if err != nil {
        fmt.Println("err2:", err)
    }
    fmt.Println([]byte(trace))
    ioutil.WriteFile("/tmp/test/b", []byte(trace), 0666)

    trackerData := &pb_union.AdTrackerInfo{}
    err = proto.Unmarshal([]byte(trace), trackerData)
    if err != nil {
        fmt.Println("err3:", err)
    }
    fmt.Println(fmt.Sprintf("%+v", trackerData))
}
*/

// vim: set noexpandtab ts=4 sts=4 sw=4 :
