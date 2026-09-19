"""
Type stubs for aliyun-log-fastpb

Fast protobuf serialization for Aliyun Log using PyO3 and quick-protobuf.
"""

from typing import Any, Dict, List, Optional, TypedDict, Union

def serialize_log_group(log_group_dict: dict) -> bytes:
    """
    Serialize a LogGroup Python dict to protobuf bytes.

    Args:
        log_group_dict: A dict containing LogItems, LogTags, Topic, and Source.
            - LogItems: List of Log entries
            - LogTags: List of LogTag metadata
            - Topic: Topic string (can be empty)
            - Source: Source string (can be empty)

    Returns:
        bytes: The serialized protobuf data.

    Example:
        >>> log_group = {
        ...     "LogItems": [{
        ...         "Time": 1234567890,
        ...         "Contents": [
        ...             {"Key": "level", "Value": "INFO"},
        ...             {"Key": "message", "Value": "Hello World"}
        ...         ]
        ...     }],
        ...     "LogTags": [{"Key": "host", "Value": "server1"}],
        ...     "Topic": "app-logs",
        ...     "Source": "192.168.1.1"
        ... }
        >>> data = serialize_log_group(log_group)
    """
    ...

def deserialize_log_group_list(data: bytes) -> dict:
    """
    Deserialize a LogGroupList protobuf bytes to Python dict.

    Returns:
        dict with "logGroupList" key containing list of LogGroup dicts.
    """
    ...

def serialize_log_group_raw(log_group_dict: dict) -> bytes:
    """
    Serialize a LogGroupRaw Python dict to protobuf bytes.

    This function supports binary data in log content values.

    Args:
        log_group_dict: A dict containing LogItems, LogTags, Topic, and Source.
            - LogItems: List of LogRaw entries (supports binary values)
            - LogTags: List of LogTag metadata
            - Topic: Topic string (can be empty)
            - Source: Source string (can be empty)

    Returns:
        bytes: The serialized protobuf data.

    Example:
        >>> log_group = {
        ...     "LogItems": [{
        ...         "Time": 1234567890,
        ...         "Contents": [
        ...             {"Key": "data", "Value": b"\\x00\\x01\\x02\\xff"}
        ...         ]
        ...     }],
        ...     "LogTags": [],
        ...     "Topic": "",
        ...     "Source": ""
        ... }
        >>> data = serialize_log_group_raw(log_group)
    """
    ...
