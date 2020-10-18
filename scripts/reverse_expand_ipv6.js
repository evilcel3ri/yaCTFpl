function RevRev6(str) {
    let arr = str.split(":");
    let filler;
    for (let i = 0; i < arr.length; i++) {
        if (arr[i] == "") {
                if (filler) {
                    arr[i] = "0000";
                } else {
                    filler = i;
                }
            } else {
            while (arr[i].length < 4) {
                arr[i] = "0" + arr[i];
            }
        }
    }
    if (filler) {
        arr.splice(filler, 1, "0000");
        while (arr.length < 8) {
            arr.splice(filler, 0, "0000");
        }
    }
    return arr.join("").split("").reverse().join(".") + ".ipv6.arpa"
}
