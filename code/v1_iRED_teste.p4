/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 10
#define PORTS 10

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO = 253;

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


typedef bit<48> macAddr_v;
typedef bit<32> ip4Addr_v;

typedef bit<31> switchID_v;
typedef bit<9> ingress_port_v;
typedef bit<9> egress_port_v;
typedef bit<9>  egressSpec_v;
typedef bit<48>  ingress_global_timestamp_v;
typedef bit<48>  egress_global_timestamp_v;
typedef bit<32>  enq_timestamp_v;
typedef bit<19> enq_qdepth_v;
typedef bit<32> deq_timedelta_v;
typedef bit<19> deq_qdepth_v;

header ethernet_h {
    macAddr_v dstAddr;
    macAddr_v srcAddr;
    bit<16>   etherType;
}

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<5>    diffserv;
    bit<1>    l4s;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_v srcAddr;
    ip4Addr_v dstAddr;
}

header nodeCount_h{
    bit<16>  count;
}

header InBandNetworkTelemetry_h {
    switchID_v swid;
    ingress_port_v ingress_port;
    egress_port_v egress_port;
    egressSpec_v egress_spec;
    ingress_global_timestamp_v ingress_global_timestamp;
    egress_global_timestamp_v egress_global_timestamp;
    enq_timestamp_v enq_timestamp;
    enq_qdepth_v enq_qdepth;
    deq_timedelta_v deq_timedelta;
    deq_qdepth_v deq_qdepth;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct queue_metadata_t {
    @field_list(0)
    bit<32> output_port;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    queue_metadata_t    queue_metadata;
}

struct headers {
    ethernet_h         ethernet;
    ipv4_h             ipv4;
    nodeCount_h        nodeCount;
    InBandNetworkTelemetry_h[MAX_HOPS] INT;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROTO: parse_count;
            default: accept;
        }
    }

    state parse_count{
        packet.extract(hdr.nodeCount);
        meta.parser_metadata.remaining = hdr.nodeCount.count;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
    }

    state parse_int {
        packet.extract(hdr.INT.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
    } 
}   
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    


    register<bit<1>> (PORTS) flagtoDrop_reg; // Register ON/OFF drop action
    counter(4, CounterType.packets) forwardingPkt; // Counter forwarding packets
    counter(4, CounterType.packets) dropPkt; // Counter packets dropped by RED
    counter(4, CounterType.packets) dropRecirc; // Counter recirculated
    
    action drop_recirc() {
        dropRecirc.count(meta.queue_metadata.output_port); //increment the counter of recirculation packets dropped
        mark_to_drop(standard_metadata);
    }
    
    action drop_regular() {
        dropPkt.count((bit<32>)standard_metadata.egress_spec); //increment the counter of regular packets dropped
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_v dstAddr, egressSpec_v port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        forwardingPkt.count((bit<32>)standard_metadata.egress_spec); //increment the counter of packets fowarded
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop_regular;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    
    apply {

        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC) {
            
            //* Cloned pkts *//
            //* Turn ON congestion flag. Write '1' in the register index port *//
            flagtoDrop_reg.write(meta.queue_metadata.output_port,1); 
            
            //* Drop cloned pkt *//
            drop_recirc();
        
        }
        else {

            ipv4_lpm.apply();

            //* Read the output port state from the register*//
            bit<1> flag;
            flagtoDrop_reg.read(flag,(bit<32>)standard_metadata.egress_spec);

            //* Check if the congestion flag is 1 (Drop ON). *//
            if (flag == 1){            
                
                //* Not for L4S and INT! Only Classic *//
                if ((hdr.ipv4.l4s != 1) && (hdr.nodeCount.isValid() == false)){

                    standard_metadata.priority = (bit<3>)7;
                    
                    //* Reset *//
                    flagtoDrop_reg.write((bit<32>)standard_metadata.egress_spec,0);   
                    
                    //* Drop future packet *//
                    drop_regular();
                }
                
                if ((hdr.ipv4.l4s == 1) && (hdr.nodeCount.isValid() == false)){

                    standard_metadata.priority = (bit<3>)0;
                }     
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    // ========== REGISTRADORES EXISTENTES ==========
    register<bit<32>>(8) QueueID;
    register<bit<16>>(PORTS) dropProbability;
    register<bit<32>>(1) targetDelay_reg;

    
    // ========== CONTADORES EXISTENTES ==========
    counter(4, CounterType.packets) recirc;
    counter(4, CounterType.packets) cloneCount;
    
    // ========== NOVOS REGISTRADORES PARA MÉTRICAS ==========
    
    // Timestamps do último pacote (para calcular IPI/IAT)
    register<bit<48>>(PORTS) last_packet_timestamp_l4s;
    register<bit<48>>(PORTS) last_packet_timestamp_classic;
    
    // Inter-Packet Interval (IPI) / Inter-Arrival Time (IAT)
    register<bit<48>>(PORTS) ipi_l4s;              // IPI médio L4S em microsegundos
    register<bit<48>>(PORTS) ipi_classic;          // IPI médio Classic em microsegundos
    
    // Contadores de Pacotes Marcados CE (Congestion Experienced)
    register<bit<64>>(PORTS) ce_marked_l4s;        // Total de pacotes L4S marcados com ECN
    
    // Contadores de Pacotes Descartados
    register<bit<64>>(PORTS) dropped_classic;      // Total de pacotes Classic dropados
    
    // Atraso de Fila (Queue Delay) separado por tipo
    register<bit<32>>(PORTS) queue_delay_l4s;      // EWMA do delay para L4S em microsegundos
    register<bit<32>>(PORTS) queue_delay_classic;  // EWMA do delay para Classic em microsegundos
    
    // Contadores Totais de Pacotes (para estatísticas)
    register<bit<64>>(PORTS) total_packets_l4s;    // Total de pacotes L4S processados
    register<bit<64>>(PORTS) total_packets_classic; // Total de pacotes Classic processados

    // ========== ACTIONS (mantém as existentes) ==========
    
    action recirculate_packet() {
        recirculate_preserving_field_list(0);
        recirc.count(meta.queue_metadata.output_port);
    }

    action clonePacket() {
        clone_preserving_field_list(CloneType.E2E, meta.queue_metadata.output_port, 0);
        cloneCount.count(meta.queue_metadata.output_port);
    }

    action add_swtrace(switchID_v swid) { 
        hdr.nodeCount.count = hdr.nodeCount.count + 1;
        hdr.INT.push_front(1);
        hdr.INT[0].setValid();
        hdr.INT[0].swid = swid;
        hdr.INT[0].ingress_port = (ingress_port_v)standard_metadata.ingress_port;
        hdr.INT[0].ingress_global_timestamp = (ingress_global_timestamp_v)standard_metadata.ingress_global_timestamp;
        hdr.INT[0].egress_port = (egress_port_v)standard_metadata.egress_port;
        hdr.INT[0].egress_spec = (egressSpec_v)standard_metadata.egress_spec;
        hdr.INT[0].egress_global_timestamp = (egress_global_timestamp_v)standard_metadata.egress_global_timestamp;
        hdr.INT[0].enq_timestamp = (enq_timestamp_v)standard_metadata.enq_timestamp;
        hdr.INT[0].enq_qdepth = (enq_qdepth_v)standard_metadata.enq_qdepth;
        hdr.INT[0].deq_timedelta = (deq_timedelta_v)standard_metadata.deq_timedelta;
        hdr.INT[0].deq_qdepth = (deq_qdepth_v)standard_metadata.deq_qdepth;
        
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 32;
    }

    table swtrace {
        actions = { 
            add_swtrace; 
            NoAction; 
        }
        default_action = NoAction();      
    }
    
    // ========== APPLY BLOCK ==========
    
    apply {
        
        // ========== REGISTRAR QUAL FILA FOI USADA (DEBUG) ==========
        QueueID.write((bit<32>)standard_metadata.qid, 1);
        
        // ========== PROCESSAR INT (se houver) ==========
        if (hdr.nodeCount.isValid()) {
            swtrace.apply();
        }
        
        // ========== VERIFICAR SE É CLONE (RECIRCULAÇÃO) ==========
        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
            meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
            recirculate_packet();
        } 
        else {
            // ========== APENAS PACOTES REGULARES (NÃO CLONES) ==========
            
            bit<32> port_idx = (bit<32>)standard_metadata.egress_port;
            bool is_l4s = (hdr.ipv4.l4s == 1);
            
            // ========== ATUALIZAR MÉTRICAS DE TIMESTAMPS E IPI/IAT ==========
            bit<48> current_time = standard_metadata.egress_global_timestamp;
            
            if (is_l4s) {
                // IPI/IAT para L4S
                bit<48> last_time;
                last_packet_timestamp_l4s.read(last_time, port_idx);
                
                if (last_time != 0) {
                    bit<48> interval = current_time - last_time;
                    bit<48> current_ipi;
                    ipi_l4s.read(current_ipi, port_idx);
                    // EWMA: IPI = (7*IPI + interval) / 8
                    bit<48> new_ipi = ((current_ipi << 3) - current_ipi + interval) >> 3;
                    ipi_l4s.write(port_idx, new_ipi);
                }
                last_packet_timestamp_l4s.write(port_idx, current_time);
                
                // Incrementar contador total de pacotes L4S
                bit<64> total_l4s;
                total_packets_l4s.read(total_l4s, port_idx);
                total_packets_l4s.write(port_idx, total_l4s + 1);
                
            } else {
                // IPI/IAT para Classic
                bit<48> last_time;
                last_packet_timestamp_classic.read(last_time, port_idx);
                
                if (last_time != 0) {
                    bit<48> interval = current_time - last_time;
                    bit<48> current_ipi;
                    ipi_classic.read(current_ipi, port_idx);
                    bit<48> new_ipi = ((current_ipi << 3) - current_ipi + interval) >> 3;
                    ipi_classic.write(port_idx, new_ipi);
                }
                last_packet_timestamp_classic.write(port_idx, current_time);
                
                // Incrementar contador total de pacotes Classic
                bit<64> total_classic;
                total_packets_classic.read(total_classic, port_idx);
                total_packets_classic.write(port_idx, total_classic + 1);
            }
            
            // ========== MEDIR DELAY DA FILA ==========
            bit<32> TARGET_DELAY = 20000; // 20ms em microsegundos
            bit<32> qdelay = (bit<32>)standard_metadata.deq_timedelta;
            
            // Ler delay anterior (EWMA separado por tipo de tráfego)
            bit<32> previousQDelay;
            if (is_l4s) {
                queue_delay_l4s.read(previousQDelay, port_idx);
            } else {
                queue_delay_classic.read(previousQDelay, port_idx);
            }
            
            // Calcular EWMA do delay: alpha = 0.5
            bit<32> EWMA = (qdelay >> 1) + (previousQDelay >> 1);
            
            // Atualizar registrador de delay
            if (is_l4s) {
                queue_delay_l4s.write(port_idx, EWMA);
            } else {
                queue_delay_classic.write(port_idx, EWMA);
            }
            
            // ========== CLASSIFICAR NÍVEL DE CONGESTIONAMENTO ==========
            bit<8> target_violation;
            
            if (EWMA <= TARGET_DELAY) {
                target_violation = 0; // Sem congestionamento
            } else if ((EWMA > TARGET_DELAY) && (EWMA < (TARGET_DELAY << 1))) {
                target_violation = 1; // Congestionamento moderado
            } else {
                target_violation = 2; // Congestionamento severo
            }
            
            // ========== PROCESSAR CONGESTIONAMENTO MODERADO ==========
            if (target_violation == 1) {
                
                bit<16> rand_classic;
                random(rand_classic, 0, 65535);
                bit<16> rand_l4s = rand_classic >> 1;
                bit<16> dropProb;
                bit<16> dropProb_temp;
                
                if (is_l4s) {
                    // ===== TRÁFEGO L4S: MARCAÇÃO ECN PROBABILÍSTICA =====
                    bool mark_decision_l4s;
                    dropProbability.read(dropProb, port_idx);
                    
                    if (rand_l4s < dropProb) {
                        // Decidiu MARCAR
                        dropProb_temp = dropProb - 1;
                        dropProbability.write(port_idx, dropProb_temp);
                        mark_decision_l4s = true;
                    } else {
                        // Decidiu NÃO MARCAR
                        dropProb_temp = dropProb + 1;
                        dropProbability.write(port_idx, dropProb_temp);
                        mark_decision_l4s = false;
                    }
                    
                    // Aplicar marcação ECN se decidiu marcar
                    if (mark_decision_l4s == true) {
                        hdr.ipv4.ecn = 3; // CE (Congestion Experienced)
                        
                        // Incrementar contador de pacotes marcados CE
                        bit<64> ce_count;
                        ce_marked_l4s.read(ce_count, port_idx);
                        ce_marked_l4s.write(port_idx, ce_count + 1);
                    }
                    
                } else {
                    // ===== TRÁFEGO CLASSIC: DROP PROBABILÍSTICO =====
                    bool drop_decision_classic;
                    dropProbability.read(dropProb, port_idx);
                    
                    if (rand_classic < dropProb) {
                        // Decidiu DROPAR
                        dropProb_temp = dropProb - 1;
                        dropProbability.write(port_idx, dropProb_temp);
                        drop_decision_classic = true;
                    } else {
                        // Decidiu NÃO DROPAR
                        dropProb_temp = dropProb + 1;
                        dropProbability.write(port_idx, dropProb_temp);
                        drop_decision_classic = false;
                    }
                    
                    // Executar drop se decidiu dropar
                    if (drop_decision_classic == true) {
                        meta.queue_metadata.output_port = port_idx;
                        clonePacket(); // Clone vai recircular e ativar flag de drop
                        
                        // Incrementar contador de pacotes dropados
                        bit<64> drop_count;
                        dropped_classic.read(drop_count, port_idx);
                        dropped_classic.write(port_idx, drop_count + 1);
                    }
                }
                
            } else if (target_violation == 2) {
                // ========== PROCESSAR CONGESTIONAMENTO SEVERO ==========
                
                if (is_l4s) {
                    // ===== L4S: MARCAR SEMPRE =====
                    hdr.ipv4.ecn = 3; // CE (Congestion Experienced)
                    
                    // Incrementar contador de pacotes marcados CE
                    bit<64> ce_count;
                    ce_marked_l4s.read(ce_count, port_idx);
                    ce_marked_l4s.write(port_idx, ce_count + 1);
                    
                } else {
                    // ===== CLASSIC: DROPAR SEMPRE =====
                    meta.queue_metadata.output_port = port_idx;
                    clonePacket(); // Clone vai recircular e ativar flag de drop
                    
                    // Incrementar contador de pacotes dropados
                    bit<64> drop_count;
                    dropped_classic.read(drop_count, port_idx);
                    dropped_classic.write(port_idx, drop_count + 1);
                }
            }
            // Se target_violation == 0, não faz nada (sem congestionamento)
        }
    }
}
/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.l4s,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.nodeCount);
        packet.emit(hdr.INT);                
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
