import redis
import json
import os


REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
QUEUE_NAME = os.getenv("QUEUE_NAME", "notifications")

try:
    redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    redis_client.ping()  # Test connection
    print("Connected to Redis successfully")
except redis.ConnectionError as e:
    print(f"Failed to connect to Redis: {e}")


async def add_to_queue(user_id: str, data: dict, ttl=1800):
    """Add data to a Redis queue."""
    try:
        redis_client.lpush(QUEUE_NAME, json.dumps(data))
        redis_client.expire(QUEUE_NAME, ttl)
        print(F"Added data to Redis queue: {QUEUE_NAME} successfully")
        return True
    except redis.exceptions.ConnectionError as e:
        print(f"Failed to connect to Redis: {e}")
    except redis.exceptions.TimeoutError as e:
        print(f"Failed to connect to Redis: {e}")
    except Exception as err:
        print(f"Failed to add to Redis Queue due to: {err}")
    return False


async def get_from_queue(username: str):
    """Retrieve data from a Redis queue."""
    try:
        length = redis_client.llen(QUEUE_NAME)

        for _ in range(length):
            message = redis_client.lpop(QUEUE_NAME)  # Pop the first message from the queue
            if not message:
                break

            try:
                message_data = json.loads(message)
                if message_data.get("sent_by") == username:
                    return message  # Return the matching message

                redis_client.rpush(QUEUE_NAME, message)
            except json.JSONDecodeError:
                print(f"Failed to parse message: {message}")

        return None  # No matching message found
    except Exception as err:
        print(f"Failed to get from Redis Queue due to: {err}")
        return None


async def read_from_queue(username: str):
    try:
        all_messages = redis_client.lrange(QUEUE_NAME, 0, -1)  # Get all messages from the queue
        matching_messages = []

        for message in all_messages:
            try:
                message_data = json.loads(message)  # Parse the JSON data
                if message_data.get("sent_by") == username:
                    matching_messages.append(message)
            except json.JSONDecodeError:
                print(f"Failed to parse message: {message}")

        return matching_messages
    except Exception as err:
        print(f"Failed to read from Redis Queue due to: {err}")
        return []


def delete_data_by_user_id(user_id: str):
    """Deletes data from Redis based on the specified user ID."""
    try:
        not_present = False
        while True:
            item = redis_client.lpop(QUEUE_NAME)
            if not item:
                not_present = True
                break

            item_data = json.loads(item)
            if item_data['user_id'] == user_id:
                continue
            redis_client.rpush(QUEUE_NAME, item)
        return {"success": True, "message": f"Data for user {user_id} deleted successfully" if not not_present else f"No data is present with this user_id: {user_id}"}

    except Exception as err:
        return {"success": False, "message": f"Data for user {user_id} deleted failed due to {err}"}


async def delete_data_by_msg(user_id: str, msg: dict):
    """Deletes data from Redis based on the specified user ID."""
    try:
        while True:
            item = redis_client.lpop(QUEUE_NAME)
            if not item:
                break

            item_data = json.loads(item)
            if item_data == msg:
                continue
            redis_client.rpush(QUEUE_NAME, item)
        return True

    except Exception as err:
        return False
