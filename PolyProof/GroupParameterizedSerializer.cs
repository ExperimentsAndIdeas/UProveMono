using System;
using UProveCrypto;
using UProveCrypto.Math;
using System.Runtime.Serialization;

namespace UProveCrypto.PolyProof
{

    public interface IGroupParameterizedSerialization : IParametrizedDeserialization
    {
        Group Group { get; set; }

        bool IsGroupSerializable { get; set; }

        /// <summary>
        /// This method will
        /// complete all deserialization tasks that require Group.
        /// </summary>
        void FinishDeserializing();

         /// <summary>
        /// Deserializer must call this method or FinishDeserializing(IssuerParameters ip) after
        /// deserialization is complete.
        /// </summary>
        /// <param name="group">Group to use if none has been serialized.  May be null if the group has been serialized.</param>
        void FinishDeserializing(Group group);
    }


    /// <summary>
    /// This abstract class is a superclass for any class that need a Group to be deserialized,
    /// which may or may not be included in the serialization of the class itself.  Subclasses of this
    /// class may be (de)serialized using IssuerParameters, CryptoSerializer, or any (de)serializer compatible
    /// with IParametrizedDeserialization.  It is possible to use a different serializer and deserializer.  The
    /// deserializer MUST call either FinishDeserialing(Group group) or FinishDeserializing(IssuerParameters ip)
    /// after deserialization is complete.
    /// 
    /// Subclasses need to implement a method with the [OnSerializing] attribute to serialize all
    /// data other than Group.  To make the Group serializable, set the IsGroupSerializable flag to true.
    /// Subclasses also need to implement the method override FinishDeserialing() to perform all deserialization tasks
    /// that require the Group (for simplicity, one can put all deserilization code in this method).
    /// 
    /// Order of serialization:
    /// 1. GroupParameterizedSerializer will serialize Group, depending on whether IsGroupSerializable is set to true.
    /// 2. The subclass method with attribute [OnSerializing] is executed
    /// 3. The subclass method with attribute [OnSerialized] is executed
    /// 
    /// Order of deserialization:
    /// 1. GroupParameterizedSerializer will try to deserialize the group.  If it is in  If it has not been serialized, it will be left as null.
    /// 2. The subclass method with attribute [OnDeserializing] is executed
    /// 3. The subclass method with attribute [OnDeserialized] is executed
    /// 4. The deserializer must call either FinishDeserialing(Group group) or FinishDeserializing(IssuerParameters ip).  At this point, only if the
    ///    group has not be included in the serialized class, GroupParameterizedSerializer will read it from the argument to FinishDeserializing.
    /// 5. GroupParameterizedSerializer will call the subclass override method FinishDeserialing().  The subclass can assume that Group is set 
    ///    to a not-null value at this point.
    /// </summary>
    [DataContract]
    public abstract class GroupParameterizedSerializer :IGroupParameterizedSerialization
    {
        /// <summary>
        /// Group
        /// </summary>
        public Group Group { get; set; }

        /// <summary>
        /// Group will be serialized during serialization if set to true, stored as null otherwise.
        /// </summary>
        public bool IsGroupSerializable
        {
            get
            {
                return _isGroupSerializable;
            }
        
            set
            {
                _isGroupSerializable=value;
            }
        }
        private bool _isGroupSerializable = true;

        /// <summary>
        /// Will not call FinishDeserializing when set to true.
        /// </summary>
        private bool IsDeserializingComplete = false;

        /// <summary>
        /// Abstract method that needs to be overriden by subclasses. This method will
        /// complete all deserialization tasks that require Group.
        /// </summary>
        public abstract void FinishDeserializing();

        /// <summary>
        /// Stores the serialized group.
        /// </summary>
        [DataMember(Name = "Group", EmitDefaultValue = false, Order = 1)]
        internal GroupSerializable _group;

        /// <summary>
        /// Serializes the Group if IsGroupSerializable is set to true.
        /// </summary>
        /// <param name="context"></param>
        [OnSerializing]
        public void SerializeGroup(StreamingContext context)
        {
			 
			// begin by serializing the group context
            if (this.IsGroupSerializable)
            {
                if (this.Group == null)
                {
                    throw new SerializationException("Private member Group must be set with a non-null group.");
                }
                _group = new GroupSerializable(this.Group);
            }
            else
            {
                this._group = null;
            }
        }

        /// <summary>
        /// Tries to deserialize the group.  If _group is not null, deserializes the group then immediately calls
        /// FinishDeserializing().  If _group is null, does nothing.
        /// </summary>
        /// <param name="context"></param>
        [OnDeserialized]
        internal void DeserializeGroup(StreamingContext context)
        {
			Console.WriteLine ("Debug: !! GroupParameterizedSerilizer-DeserializeGroup called");

            // Try to finish deserializing
            this.IsDeserializingComplete = false;
            this.DeserializeGroup(null, false);
        }

        /// <summary>
        /// Tries to set Groupo.  Preference is given to a serialized group. If none exists,
        /// will use the provided argument.
        /// </summary>
        /// <param name="group">Group to use if no group is deserialized</param>
        /// <param name="throwExceptionOnFailure"></param>
        private void DeserializeGroup(Group group, bool throwExceptionOnFailure=true)
        {
			Console.WriteLine ("Debug: GroupParameterizedSerilizer-DeserializeGroup2 called");

            // Group already set. Do nothing.
            if (this.Group != null)
            {
                return;
            }

            // Try to deserialize _group
            if (this._group != null)
            {
                this.Group = this._group.ToGroup();
                this.IsGroupSerializable = true;
                return;
            }

            // Try to use provided argument
            if (group != null)
            {
                this.Group = group;
                this.IsGroupSerializable = false;
                return;
            }

            // May throw exeception
            if (throwExceptionOnFailure)
            {
                throw new SerializationException("Could not deserialize Group.");
            }

        }

        /// <summary>
        /// Deserializer must call this method or FinishDeserializing(IssuerParameters ip) after
        /// deserialization is complete.
        /// </summary>
        /// <param name="group">Group to use if none has been serialized.  May be null if the group has been serialized.</param>
        public void FinishDeserializing(Group group)
        {
			Console.WriteLine ("Debug: GroupParameterizedSerilizer-FinishDeserializing called");

            if (this.IsDeserializingComplete == true)
            {
                return;
            }

            this.DeserializeGroup(group);
            if (this.Group == null)
            {
                throw new SerializationException("Failed to deserialize group.");
            }

            this.FinishDeserializing();
            this.IsDeserializingComplete = true;
        }

        /// <summary>
        /// Deserializer must call this method or FinishDeserializing(Group group) after
        /// deserialization is complete.  This method is for UProve cross-compatibility.
        /// </summary>
        /// <param name="ip">ip.Gq contains the group to use if none has been serialized.  
        /// Argument ip or ip.Gq may be null if the group has been serialized.</param>
        void IParametrizedDeserialization.FinishDeserialization(IssuerParameters ip)
        {
			Console.WriteLine ("Debug: GroupParameterizedSerilizer-FinishDeserialization(ip) called");

            if (ip == null)
            {
                FinishDeserializing(null);
            }
            FinishDeserializing(ip.Gq);
            this.IsDeserializingComplete = true;
        }
    }
}
