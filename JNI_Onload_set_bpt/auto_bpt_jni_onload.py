import idc
import idautils
import ida_bytes
import ida_funcs
# time: 2023/1/31 
# author: iyue
# 基于aosp10 - 12  源码符号都一样 其他可以自己找一下 
def helloIdaPython():
    print("---------------- start --------------------")

def findModules(name):
    """
        获取指定模块
    """
    # module = idc.get_first_module()
    # print("get first module : {}".format(module))
    # while (module!=None):
    #     moduleName = idc.get_module_name(module)
    #     print("find module name:{}".format(moduleName))
    #     if name in moduleName:
    #         return module
    #     module = idc.get_next_module(module)
    # return None
    
    modules = idc.get_event_module_base()
    for module in modules:
        print(module)

def setJniOnloadBt():
    
    # 1. 获取数据段起始和结束位置
    rodata_ea_start = 0
    rodata_ea_end = 0
    local_sections = idautils.Segments()
    for section in local_sections:
        seg_name = idc.get_segm_name(section)
        # print(seg_name)
        
        if seg_name == '.rodata':
            rodata_ea_start = section
            rodata_ea_end = idc.get_segm_end(rodata_ea_start)
            # print("\t[iyue] find .rodata segment:0x%X"%(rodata_ea_start))
            print("\t[iyue] find .rodata segment:0x%X - 0x%X"%(rodata_ea_start,rodata_ea_end))
            break
            
    if rodata_ea_start == 0:
        print ("\t[iyue] can not locate .rodata segment")
        return False
    
    # 2. 在rodata段中搜索字符串
    jniOnloadStrAddr = 0
    eaOffset = rodata_ea_start
    # for debug 
    # file = open(r"C:\Users\l\Tools\SCRIPT\test.log",'w')
    print ("\t[iyue] start find: [Calling JNI_OnLoad in \" ")
    while eaOffset<rodata_ea_end:
        currentString = idc.get_strlit_contents(eaOffset)
        if currentString == None:
            eaOffset+=1
            continue
        sstr = bytes(currentString).decode('utf-8')
        if "[Calling JNI_OnLoad in \"" == sstr:
            print("\t[iyue] found strlit: %s addr:0x%X"%(sstr,eaOffset))
            jniOnloadStrAddr = eaOffset
            break
        # file.write(sstr+'\n')
        eaOffset+=len(sstr)
    # file.flush()
    # file.close()
    if jniOnloadStrAddr == 0:
        print("\t[iyue] not found strlit: %s"%("[Calling JNI_OnLoad in \""))
        return False
    
    # 3. 获取jni关键字符串的引用地址
    xrefAddr=0
    allXref = idautils.XrefsTo(jniOnloadStrAddr)
    # 通过分析源码可知 前两个挨着的 第三个属于 
    for xref in allXref:
        print(xref.type, idautils.XrefTypeName(xref.type),'from', hex(xref.frm), 'to', hex(xref.to))
        print('\t[iyue] first ref in:0x%X'%xref.frm)
        xrefAddr = xref.frm
        break
    if xrefAddr == 0:
        print("\t[iyue] not found %s Reference!"%("[Calling JNI_OnLoad in \""))
        return False
    
    # 4. 找到跳转后的地址
    # int version = (*jni_on_load)(this, nullptr); 可以看到函数地址是一个变量
    funcItems = idautils.FuncItems(xrefAddr) #获取xref引用地址所在函数的所有地址
    goNextAddr=0
    for itermAddr in funcItems:
        if itermAddr >= xrefAddr:
            # 跳转指令opcode 2 个字节
            # print(itermAddr)
            opcode = ida_bytes.get_word(itermAddr)
            # print(opcode)
            if 0xE4B7 == opcode:
                print("\t[iyue] ",hex(opcode),idc.GetDisasm(itermAddr)) 
                gotoAddr = idc.GetDisasm(itermAddr).split('_')[1]
                goNextAddr= hex(int('0x'+gotoAddr,16))
                print("\t[iyue] find go next addr:",goNextAddr)
                break
            # 兼容64位libart.so
            # print(opcode64)
            opcode64 = ida_bytes.get_32bit(itermAddr)
            if 0x17fffe17 == opcode64:
                print("\t[iyue] ",hex(opcode64),idc.GetDisasm(itermAddr)) 
                gotoAddr = idc.GetDisasm(itermAddr).split('_')[1]
                goNextAddr= hex(int('0x'+gotoAddr,16))
                print("\t[iyue] find go next addr:",goNextAddr)
                break
                
    if goNextAddr==0:
        print("\t[iyue] no found go next addr !")
        return False

    # 5. 获取函数起始和结束位置
    goNextAddr = int(goNextAddr,16)
    tmpFuncName = idc.get_func_name(goNextAddr)
    if 'LoadNativeLibrary' in tmpFuncName:
        LoadNativeLibraryFuncStart = idc.get_func_attr(goNextAddr,idc.FUNCATTR_START)
        LoadNativeLibraryFuncEnd = idc.get_func_attr(goNextAddr,idc.FUNCATTR_END)
    
    # 6.找到jni_onload 调用位置
    callJniOnloadAddr=0
    while goNextAddr < LoadNativeLibraryFuncEnd:
        ssstr = idc.GetDisasm(goNextAddr)
        print('\t[iyue] 0x%X %s'%(goNextAddr,ssstr))
        #print("'%s'"%ssstr)
        if 'BLX' in ssstr and 'R' in ssstr or 'BLR' in ssstr and 'X' in ssstr:
            callJniOnloadAddr = goNextAddr
            print("\t[iyue] find call jni_onload  addr:",goNextAddr)
            break
        goNextAddr+=1

    if callJniOnloadAddr == 0:
        print("\t[iyue] no found call jni_onload fial !")
        return False
    # 7. 在调用位置下断点
    idc.add_bpt(callJniOnloadAddr)
    print('\t[iyue] add bpt in:%s'%ssstr)
    return True
    
def main():
    print("---------------- start --------------------")
    # findModules('libart.so')
    setJniOnloadBt()
    print("---------------- end --------------------")
    pass


    

if __name__ == "__main__":
    main()
    
   
        