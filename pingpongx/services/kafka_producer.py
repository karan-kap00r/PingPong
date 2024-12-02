import os
from kafka import KafkaProducer
from kafka.admin import KafkaAdminClient, NewTopic
from pingpongx.utils import sanitize_topic_name

TOPIC_NAME = os.getenv('TOPIC_NAME')
BROKER = 'kafka:9092'
DEFAULT_PARTITIONS = 3
DEFAULT_REPLICATION_FACTOR = 1

producer = KafkaProducer(
    bootstrap_servers='kafka:9092',  # Use the advertised listener
    retries=5,                       # Retry connecting to the broker
    request_timeout_ms=20000,        # Extend timeout for slow startup
    api_version=(0, 10, 1),          # API version
    metadata_max_age_ms=300000       # Cache metadata for 5 minutes
)


async def send_event(user_id: str, message: str):
    """Send an event to a Kafka topic."""
    try:
        topic_name = await create_topic_if_not_exists(TOPIC_NAME)
        future = producer.send(topic_name, value=message.encode('utf-8'))
        record_metadata = future.get(timeout=10)
        print(f"Message sent to topic {record_metadata.topic}, partition {record_metadata.partition}, offset {record_metadata.offset}")
        return True
    except Exception as e:
        print(f"Failed to send message to Kafka: {e}")
        return False


async def topic_exists(topic_name: str):
    admin_client = KafkaAdminClient(bootstrap_servers='kafka:9092', api_version=(0, 10, 1))
    topics = admin_client.list_topics()
    return topic_name in topics


async def create_topic_if_not_exists(topic_name):
    """Check if the topic exists and create it if necessary."""
    try:
        admin_client = KafkaAdminClient(bootstrap_servers='kafka:9092', api_version=(0, 10, 1))
        existing_topics = admin_client.list_topics()
        topic_name = sanitize_topic_name(topic_name)

        if topic_name not in existing_topics:
            print(f"Topic '{topic_name}' does not exist. Creating it...")

            # Create the topic
            topic = NewTopic(
                name=topic_name,
                num_partitions=DEFAULT_PARTITIONS,
                replication_factor=DEFAULT_REPLICATION_FACTOR
            )
            admin_client.create_topics([topic])
            print(f"Topic '{topic_name}' successfully created.")
        else:
            print(f"Topic '{topic_name}' already exists.")
        return topic_name
    except Exception as e:
        print(f"Failed to check or create topic '{topic_name}': {e}")
        return None
