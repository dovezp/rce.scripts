#!/usr/bin/python
# coding=utf-8

"""
brief:          meta - builder - strings
author:         dovezp
contact:        https://github.com/dovezp
version:        22/OCT/2018
license:        GNU Lesser General Public License v3 (LGPL-3.0)
"""


try:
    import idc
    import idaapi
    import idautils
except ImportError as e:
    raise Exception("ERROR.ImportException: " + e.message)
except Exception as e:
    raise Exception("ERROR.UnhandledImportException: " + e.message)


# --------------------------------------------------------------------------------------------------
"""
Strings Exceptions
"""


class StringsInvalidTargetNameException(Exception):
    """
    Raise when accessing non-existing segment name
    """

    def __init__(self, level="ERROR", message="Target segment name(s) do not exist."):
        super(StringsInvalidTargetNameException, self).__init__(message)
        self.level = level
        self.name = "StringsInvalidTargetNameException"
        self.message = message

    def __str__(self):
        return self.level + "." + self.name + ": " + self.message


class StringsInvalidTargetAreaException(Exception):
    """
    Raise when accessing invalid area ranges
    """

    def __init__(self, level="ERROR", message="Target segment area(s) are malformed or invalid."):
        super(StringsInvalidTargetAreaException, self).__init__(message)
        self.level = level
        self.name = "StringsInvalidTargetAreaException"
        self.message = message

    def __str__(self):
        return self.level + "." + self.name + ": " + self.message


class StringsTargetAlreadyNamedException(Exception):
    """
    Raise when accessing already named location
    """

    def __init__(self, level="WARNING", message="Target has previously been named."):
        super(StringsTargetAlreadyNamedException, self).__init__(message)
        self.level = level
        self.name = "StringsTargetAlreadyNamedException"
        self.message = message

    def __str__(self):
        return self.level + "." + self.name + ": " + self.message


class StringsTargetFailedToBeNamedException(Exception):
    """
    Raise when accessing already named location
    """

    def __init__(self, level="WARNING", message="Target could not be named."):
        super(StringsTargetFailedToBeNamedException, self).__init__(message)
        self.level = level
        self.name = "StringsTargetFailedToBeNamedException"
        self.message = message

    def __str__(self):
        return self.level + "." + self.name + ": " + self.message


# --------------------------------------------------------------------------------------------------
"""
Strings Class
"""


class Strings(object):

    def __init__(self, str_target_segment_name):
        self.__target = ""
        self.__area = []
        self.__temp_chain_holder = []
        self.update(str_target_segment_name)

    # ..........................................

    @staticmethod
    def __fetch_area(str_segment_name):
        # TODO
        area = []
        for segment in idautils.Segments():
            if idc.SegName(int(segment)) == str_segment_name:
                area.append((int(idc.SegStart(int(segment))), int(idc.SegEnd(int(segment)))))
        return area

    # ..........................................

    @staticmethod
    def __is_unique_reference(int_address):
        reference_count = len(list(idautils.DataRefsTo(int_address)))
        if reference_count == 1:
            return True
        return False

    def __is_valid_reference(self, int_address):
        if idc.isCode(idc.GetFlags(int_address)):
            if idc.SegName(int_address) == self.__target:
                if idc.GetFunctionAttr(int_address, idc.FUNCATTR_START) != idc.BADADDR:
                    return True
        return False

    # ..........................................

    def __set_target(self, str_target_segment_name):
        if str_target_segment_name == "":
            return False
        for segment in idautils.Segments():
            if idc.SegName(int(segment)) == str_target_segment_name:
                self.__target = str_target_segment_name
                return True
        return False

    def __set_area(self, list_area):
        if len(list_area) == 0:
            return False
        for start, end in list_area:
            if start == idc.BADADDR or end == idc.BADADDR:
                return False
        self.__area = list_area
        return True

    # ..........................................

    def __get_area(self):
        return self.__area

    def __get_target(self):
        return self.__target

    # ..........................................

    def __chain(self, int_address, int_reference_count):
        if int_reference_count == 0:
            return False
        elif int_reference_count == 1:
            next_address = int(idc.RfirstB(idc.GetFunctionAttr(int_address, idc.FUNCATTR_START)))
            next_name = str(idc.GetFunctionName(next_address))
            self.__temp_chain_holder.append(next_name)
            i = len(list(idautils.CodeRefsTo(idc.GetFunctionAttr(next_address, idc.FUNCATTR_START), 0)))
            return self.__chain(next_address, i)
        else:
            return True

    def __validate(self, int_address, int_references_goal):
        function_usage = idautils.CodeRefsTo(idc.GetFunctionAttr(int_address, idc.FUNCATTR_START), 0)
        current_function_references = len(list(function_usage))
        self.__chain(int_address, current_function_references)
        if len(self.__temp_chain_holder) == int(int_references_goal):
            self.__temp_chain_holder = []
            return True
        self.__temp_chain_holder = []
        return False

    def fetch(self):
        string_references = []
        for s in idautils.Strings():
            if self.__is_unique_reference(s.ea):
                first_reference = int(idc.DfirstB(s.ea))
                if self.__is_valid_reference(first_reference):
                    current_function_name = str(idc.GetFunctionName(first_reference))
                    if not current_function_name.startswith("sub_") or \
                            not current_function_name.startswith("loc_") or \
                            not current_function_name.startswith("unk_"):
                        function_usage = idautils.CodeRefsTo(idc.GetFunctionAttr(first_reference, idc.FUNCATTR_START), 0)
                        current_function_references = len(list(function_usage))
                        self.__chain(first_reference, current_function_references)
                        string_references.append({"string": str(s),
                                                  "function": current_function_name,
                                                  "chain": self.__temp_chain_holder})
                        self.__temp_chain_holder = []
        return string_references

    def match(self, list_string_references):
        for s in idautils.Strings():
            if self.__is_unique_reference(s.ea):
                first_reference = int(idc.DfirstB(s.ea))
                if self.__is_valid_reference(first_reference):
                    for string_ref in list_string_references:
                        if str(s) == string_ref["string"]:
                            if self.__validate(first_reference, len(string_ref["chain"])):
                                function_head = (idc.GetFunctionAttr(first_reference, idc.FUNCATTR_START))
                                current_function_name = str(idc.GetFunctionName(function_head))
                                if current_function_name.startswith("sub_"):
                                    if idc.MakeName(function_head, str(string_ref["function"])) == 0:
                                        e = StringsTargetFailedToBeNamedException("Target function at address: " +
                                                                                  hex(int(function_head)) +
                                                                                  " could not be named.")
                                        print(e)
                                        print("------------------------------------------------------------")
                                    for chain in string_ref["chain"]:
                                        function_head = int(idc.RfirstB(idc.GetFunctionAttr(function_head, idc.FUNCATTR_START)))
                                        current_function_name = str(idc.GetFunctionName(function_head))
                                        if current_function_name.startswith("sub_"):
                                            if idc.MakeName(function_head, str(chain)) == 0:
                                                e = StringsTargetFailedToBeNamedException("Target chain at address: " +
                                                                                          hex(int(function_head)) +
                                                                                          " could not be named.")
                                                print(e)
                                                print("------------------------------------------------------------")

                                        else:
                                            e = StringsTargetAlreadyNamedException("Target chain at address: " +
                                                                                   hex(int(function_head)) +
                                                                                   " has already been named.")
                                            print(e)
                                            print("------------------------------------------------------------")
                                else:
                                    e = StringsTargetAlreadyNamedException("Target at address: " +
                                                                           hex(int(function_head)) +
                                                                           " has already been named.")
                                    print(e)
                                    print("------------------------------------------------------------")

    # ..........................................

    def update(self, str_target_segment_name):
        if not self.__set_target(str_target_segment_name):
            raise StringsInvalidTargetNameException()
        if not self.__set_area(self.__fetch_area(str_target_segment_name)):
            raise StringsInvalidTargetAreaException()
        return True


# --------------------------------------------------------------------------------------------------
"""
"""


"""
u = Strings(".text")
ss = u.fetch()
u.match(ss)
"""


# --------------------------------------------------------------------------------------------------
