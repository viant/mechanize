import Foundation
import AppKit
import Darwin
import Security

/// Chrome alone may run its canonical signed main image through a hardlink.
/// Kernel paths remain actual paths. Neither names nor substrings establish trust.
enum MigrationChromeTrust {
    static let googleSignerRequirement = "identifier \"com.google.Chrome\" and anchor apple generic and certificate leaf[subject.OU] = \"EQHXZ8M8AV\""
    static func adminGroup() -> gid_t? {
        var value=group(),result:UnsafeMutablePointer<group>?;var buffer=[CChar](repeating:0,count:16384)
        return buffer.withUnsafeMutableBufferPointer { bytes in
            guard getgrnam_r("admin",&value,bytes.baseAddress,bytes.count,&result)==0,result != nil,let name=value.gr_name,String(cString:name)=="admin" else{return nil};return value.gr_gid
        }
    }
    static func modeAllowed(_ mode:mode_t,_ gid:gid_t,_ admin:gid_t?) -> Bool {
        guard mode & 0o7002 == 0 else{return false}
        return mode & 0o020 == 0 || admin == gid
    }
}
final class MigrationChromeImageFile {
    let fd: Int32
    let original: stat
    private var descriptors: [Int32] = []
    private var entries: [(Int32,String,Int32,stat)] = []
    init(_ path:String)throws {
        guard MigrationRuntimeConsoleManifest.path(path) else{throw MigrationConsoleError.unavailable}
        var opened:[Int32]=[],links:[(Int32,String,Int32,stat)]=[];var accepted=false
        defer{if !accepted{opened.forEach{Darwin.close($0)}}}
        let root=Darwin.open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);guard root>=0 else{throw MigrationConsoleError.unavailable};opened.append(root)
        var parent=root
        let parts=path.split(separator:"/").map(String.init)
        for (index,part) in parts.enumerated() {
            let directory=index<parts.count-1
            let next=openat(parent,part,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(directory ? O_DIRECTORY:O_NONBLOCK));guard next>=0 else{throw MigrationConsoleError.unavailable};opened.append(next)
            var info=stat();guard fstat(next,&info)==0 else{throw MigrationConsoleError.unavailable}
            links.append((parent,part,next,info));parent=next
        }
        var info=stat();guard fstat(parent,&info)==0,info.st_mode&S_IFMT==S_IFREG,info.st_nlink>=1,
              info.st_uid==0 || info.st_uid==getuid(),MigrationChromeTrust.modeAllowed(info.st_mode,info.st_gid,MigrationChromeTrust.adminGroup()),info.st_mode&0o111 != 0 else{throw MigrationConsoleError.unavailable}
        fd=parent;original=info;descriptors=opened;entries=links;accepted=true
    }
    deinit{descriptors.forEach{Darwin.close($0)}}
    static func same(_ a:stat,_ b:stat)->Bool {
        a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_uid==b.st_uid && a.st_gid==b.st_gid && a.st_mode==b.st_mode && a.st_nlink==b.st_nlink && a.st_size==b.st_size && a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec && a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec
    }
    func revalidate()throws {
        for (parent,name,fd,before) in entries {
            var descriptor=stat(),entry=stat()
            guard fstat(fd,&descriptor)==0,fstatat(parent,name,&entry,AT_SYMLINK_NOFOLLOW)==0,
                  before.st_dev == descriptor.st_dev, before.st_ino == descriptor.st_ino,
                  descriptor.st_dev == entry.st_dev, descriptor.st_ino == entry.st_ino,
                  before.st_uid == descriptor.st_uid, before.st_gid == descriptor.st_gid, before.st_mode == descriptor.st_mode,
                  (before.st_mode & S_IFMT == S_IFDIR || Self.same(before,descriptor)),
                  (entry.st_mode & S_IFMT == S_IFDIR || Self.same(descriptor,entry)) else{throw MigrationConsoleError.unavailable}
        }
    }
}
extension MigrationObserverOS {
    static func chromeImage(_ pid:Int32,_ token:String,_ canonical:String,_ requirement:String)throws->MigrationShutdownIdentity {
        guard try birth(pid)==token,NSRunningApplication(processIdentifier:pid)?.bundleIdentifier=="com.google.Chrome",
              !requirement.isEmpty,requirement.utf8.count<=4096 else{throw MigrationConsoleError.unavailable}
        func kernelPath()throws->String {
            var buffer=[CChar](repeating:0,count:4096);guard proc_pidpath(pid,&buffer,UInt32(buffer.count))>0 else{throw MigrationConsoleError.unavailable};return String(cString:buffer)
        }
        let actual=try kernelPath(),canonicalFile=try MigrationChromeImageFile(canonical),actualFile=try MigrationChromeImageFile(actual)
        guard MigrationChromeImageFile.same(canonicalFile.original,actualFile.original) else{throw MigrationConsoleError.unavailable}
        let effective = canonicalFile.original.st_mode & 0o020 == 0 ? requirement : "("+requirement+") and ("+MigrationChromeTrust.googleSignerRequirement+")"
        var rule:SecRequirement?,fixed:SecStaticCode?,running:SecCode?
        guard SecRequirementCreateWithString(effective as CFString,[],&rule)==errSecSuccess,let rule,
              SecStaticCodeCreateWithPath(URL(fileURLWithPath:canonical) as CFURL,[],&fixed)==errSecSuccess,let fixed,
              SecStaticCodeCheckValidity(fixed,SecCSFlags(rawValue:kSecCSStrictValidate|kSecCSCheckAllArchitectures),rule)==errSecSuccess else{throw MigrationConsoleError.unavailable}
        try canonicalFile.revalidate();try actualFile.revalidate()
        guard SecCodeCopyGuestWithAttributes(nil,[kSecGuestAttributePid:pid] as CFDictionary,[],&running)==errSecSuccess,let running,
              SecCodeCheckValidity(running,SecCSFlags(rawValue:kSecCSStrictValidate),rule)==errSecSuccess else{throw MigrationConsoleError.unavailable}
        try canonicalFile.revalidate();try actualFile.revalidate()
        guard try birth(pid)==token,try kernelPath()==actual else{throw MigrationConsoleError.unavailable}
        return MigrationShutdownIdentity(pid:pid,uid:getuid(),birth:token,executable:actual,requirement:requirement)
    }
}
