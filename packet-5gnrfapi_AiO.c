#include "config.h" 

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>

void proto_register_5gfapi(void);
void proto_reg_handoff_5gfapi(void);

#define NR_FAPI_PORT 12078
#define NR_FAPI_HEADER_LENGTH 8

static int proto_5gfapi = -1;

/* These are for the subtrees */
static gint ett_5gfapi_message_tree = -1;
static gint ett_5gfapi_p7_p5_message_header = -1;
static gint ett_5gfapi_ul_dci_message_body = -1;
static gint ett_5gfapi_pdu_list = -1;
static gint ett_5gfapi_pdu_idx = -1;
static gint ett_5gfapi_pdcch_pdu_config = -1;
static gint ett_5gfapi_ul_dci_pdcch_pdu_bwp = -1;
static gint ett_5gfapi_ul_dci_pdcch_pdu_coreset = -1;
static gint ett_5gfapi_dl_dci_structure = -1;
static gint ett_5gfapi_dl_dci_beamforming_info = -1;
static gint ett_5gfapi_dl_dci_tx_pwr_info = -1;
static gint ett_5gfapi_dl_tti_request = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu_bwp = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu_Codeword_info = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu_Codeword = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu_dmrs = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu_allocFreqDomain = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu_allocTimeDomain = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu_ptrs = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu_txPower = -1;
static gint ett_5gfapi_dl_tti_pdsch_pdu_cbgFields = -1;

/*UL_TTI.Request*/
static gint  ett_5gfapi_UL_tti_Msg_body = -1;
static gint  ett_5gfapi_Number_of_PDUs = -1;
static gint  ett_5gfapi_UL_tti_Prach_pdu = -1;
static gint  ett_5gfapi_UL_tti_beamforming = -1;
static gint  ett_5gfapi_UL_tti_Pusch_Pdu = -1;
static gint  ett_5gfapi_UL_tti_Bwp = -1;
static gint  ett_5gfapi_UL_tti_PUSCH_Info = -1;
static gint  ett_5gfapi_UL_tti_PRACH_PDU_DMRS = -1;
static gint  ett_5gfapi_UL_tti_PUSCH_Alloc = -1;
static gint  ett_5gfapi_UL_tti_Res_Alloc = -1;
static gint  ett_5gfapi_UL_tti_PUCCH_PDU_Struct = -1;
static gint  ett_5gfapi_UL_tti_Pucch_Allocation_Fd = -1;
static gint  ett_5gfapi_UL_tti_Pucch_Allocation_td = -1;
static gint  ett_5gfapi_UL_tti_Hopping_Information = -1;
static gint  ett_5gfapi_UL_tti_PUCCH_PDU_DMRS = -1;
static gint  ett_5gfapi_UL_tti_Srs_pdu = -1;


static int hf_5gfapi_message_tree = -1;
static int hf_5gfapi_p7_p5_message_header = -1;
static int hf_5gfapi_p7_p5_message_header_num_of_msgs = -1;
static int hf_5gfapi_p7_p5_message_header_phy_id = -1;
static int hf_5gfapi_p7_p5_message_header_message_id = -1;
static int hf_5gfapi_p7_p5_message_header_message_length = -1;
static int hf_5gfapi_error_code = -1;

/*DL_TTI and UL_DCI*/
static int hf_5gfapi_num_pdus = -1;
static int hf_5gfapi_num_group = -1;
static int hf_5gfapi_dl_tti_request = -1;
static int hf_5gfapi_dl_tti_request_pdcch_pdu_bwp_info = -1;
static int hf_5gfapi_dl_tti_request_pdu_info = -1;
static int ett_5gfapi_dl_tti_request_pdu_info = -1;
static int hf_5gfapi_pdcch_pdu_bwp_size = -1;
static int hf_5gfapi_pdcch_pdu_bwp_start = -1;
static int hf_5gfapi_pdcch_pdu_bwp_subcarrier_spacing = -1;
static int hf_5gfapi_pdcch_pdu_bwp_cyclic_prefix = -1;

/* SSB PDU INFO */
static int hf_5gfapi_pdcch_pdu_ssb = -1;
static int hf_5gfapi_pdcch_pdu_ssb_phy_cell_id = -1;
static int hf_5gfapi_pdcch_pdu_ssb_beta_pss = -1;
static int hf_5gfapi_pdcch_pdu_ssb_block_index = -1;
static int hf_5gfapi_pdcch_pdu_ssb_subcarrier_offset = -1;
static int hf_5gfapi_pdcch_pdu_ssb_offset_point_a = -1;
static int hf_5gfapi_pdcch_pdu_ssb_bch_payload_flag = -1;

static int hf_5gfapi_pdcch_pdu_mib = -1;
static int hf_5gfapi_pdcch_pdu_mib_bch_payload = -1;
static int hf_5gfapi_pdcch_pdu_mib_dmrs_type_a_psition = -1;
static int hf_5gfapi_pdcch_pdu_mib_pdcch_config_sib1 = -1;
static int hf_5gfapi_pdcch_pdu_mib_cell_barred = -1;
static int hf_5gfapi_pdcch_pdu_mib_intra_freq_reselection = -1;

/* CSI RS INFO */
static int hf_5gfapi_csi_rs_bwp_pdu = -1;
static int hf_5gfapi_csi_rs_bwp_pdu_size = -1;
static int hf_5gfapi_csi_rs_bwp_pdu_start = -1;
static int hf_5gfapi_csi_rs_bwp_pdu_subcarrier_spacing = -1;
static int hf_5gfapi_csi_rs_bwp_pdu_cyclic_prefix = -1;

static int hf_5gfapi_csi_rs_pdu = -1;
static int hf_5gfapi_csi_rs_pdu_start_rb = -1;
static int hf_5gfapi_csi_rs_pdu_nr_of_rbs = -1;
static int hf_5gfapi_csi_rs_pdu_csi_type = -1;
static int hf_5gfapi_csi_rs_pdu_row = -1;
static int hf_5gfapi_csi_rs_pdu_freq_domain = -1;
static int hf_5gfapi_csi_rs_pdu_symbL0 = -1;
static int hf_5gfapi_csi_rs_pdu_symbl1 = -1;
static int hf_5gfapi_csi_rs_pdu_cdm_type = -1;
static int hf_5gfapi_csi_rs_pdu_freq_density = -1;
static int hf_5gfapi_csi_rs_pdu_scramb_id = -1;

static int hf_5gfapi_csi_rs_pdu_tx_power_info = -1;
static int hf_5gfapi_csi_rs_pdu_tx_power_info_power_control_offset = -1;
static int hf_5gfapi_csi_rs_pdu_tx_power_info_power_control_offsetSS = -1;

/*UL DCI*/
static int hf_5gfapi_sfn = -1;
static int hf_5gfapi_slot = -1;
static int hf_5gfapi_num_pdcch_pdu = -1;
static int hf_5gfapi_ul_dci_message_body = -1;
static int hf_5gfapi_pdu_list = -1;
static int hf_5gfapi_pdu_type = -1;
static int hf_5gfapi_pdu_size = -1;
static int hf_5gfapi_pdu_idx = -1;
static int hf_5gfapi_pdcch_pdu_config = -1;
static int hf_5gfapi_ul_dci_pdcch_pdu_bwp = -1;
static int hf_5gfapi_bwp_size = -1;
static int hf_5gfapi_bwp_start = -1;
static int hf_5gfapi_subcarrier_spacing = -1;
static int hf_5gfapi_cyclic_prefix = -1;
static int hf_5gfapi_ul_dci_pdcch_pdu_coreset = -1;
static int hf_5gfapi_StartSymbolIndex = -1;
static int hf_5gfapi_DurationSymbols = -1;
static int hf_5gfapi_FreqDomainResource = -1;
static int hf_5gfapi_CceRegMappingType = -1;
static int hf_5gfapi_RegBundleSize = -1;
static int hf_5gfapi_InterleaverSize = -1;
static int hf_5gfapi_CoreSetType = -1;
static int hf_5gfapi_ShiftIndex = -1;
static int hf_5gfapi_precoderGranularity = -1;
static int hf_5gfapi_numDlDci = -1;
static int hf_5gfapi_dl_dci_structure = -1;
static int hf_5gfapi_rnti = -1;
static int hf_5gfapi_scramblingId = -1;
static int hf_5gfapi_ScramblingRNTI = -1;
static int hf_5gfapi_CceIndex = -1;
static int hf_5gfapi_AggregationLevel = -1;
static int hf_5gfapi_dl_dci_beamforming_info = -1;
static int hf_5gfapi_numPRGs = -1;
static int hf_5gfapi_prgSize = -1;
static int hf_5gfapi_digBFInterfaces = -1;
static int hf_5gfapi_PMidx = -1;
static int hf_5gfapi_beamIdx = -1;
static int hf_5gfapi_dl_dci_tx_pwr_info = -1;
static int hf_5gfapi_beta_pdcch_1_0 = -1;
static int hf_5gfapi_powerControlOffsetSS = -1;
static int hf_5gfapi_PayloadSizeBits = -1;
static int hf_5gfapi_Payload = -1;

/** PDSCH PDU */
static int hf_5gfapi_dl_tti_pdsch_pdu = -1;
static int hf_5gfapi_dl_tti_request_pduBitmap = -1;

static int hf_5gfapi_dl_tti_request_rnti = -1;
static int hf_5gfapi_dl_tti_request_pdu_index = -1;
static int hf_5gfapi_dl_tti_pdsch_pdu_bwp = -1;
static int hf_5gfapi_dl_tti_request_bwp_size = -1;
static int hf_5gfapi_dl_tti_request_bwp_start = -1;
static int hf_5gfapi_dl_tti_request_sub_carrier_spacing = -1;
static int hf_5gfapi_dl_tti_request_cyclic_prefix = -1;

static int hf_5gfapi_dl_tti_pdsch_pdu_Codeword_info = -1;
static int hf_5gfapi_dl_tti_request_nrOfCodewords = -1;
static int hf_5gfapi_dl_tti_pdsch_pdu_Codeword = -1;
static int hf_5gfapi_dl_tti_request_targetCodeRate = -1;
static int hf_5gfapi_dl_tti_request_qamModOrder = -1;
static int hf_5gfapi_dl_tti_request_mcsIndex = -1;
static int hf_5gfapi_dl_tti_request_mcsTable = -1;
static int hf_5gfapi_dl_tti_request_rvIndex = -1;
static int hf_5gfapi_dl_tti_request_tbSize = -1;

static int hf_5gfapi_dl_tti_request_dataScramblingId = -1;
static int hf_5gfapi_dl_tti_request_nrOfLayers = -1;
static int hf_5gfapi_dl_tti_request_transmissionScheme = -1;
static int hf_5gfapi_dl_tti_request_refPoint = -1;

static int hf_5gfapi_dl_tti_pdsch_pdu_dmrs = -1;
static int hf_5gfapi_dl_tti_request_dlDmrsSymbPos = -1;
static int hf_5gfapi_dl_tti_request_dmrsConfigType = -1;
static int hf_5gfapi_dl_tti_request_dlDmrsScramblingId = -1;
static int hf_5gfapi_dl_tti_request_SCID = -1;
static int hf_5gfapi_dl_tti_request_numDmrsCdmGrpsNoData = -1;
static int hf_5gfapi_dl_tti_request_dmrsPorts = -1;

static int hf_5gfapi_dl_tti_pdsch_pdu_allocFreqDomain = -1;
static int hf_5gfapi_dl_tti_request_resourceAlloc = -1;
static int hf_5gfapi_dl_tti_request_rbBitmap = -1;
static int hf_5gfapi_dl_tti_request_rbStart = -1;
static int hf_5gfapi_dl_tti_request_rbSize = -1;
static int hf_5gfapi_dl_tti_request_VRBtoPRBMapping = -1;

static int hf_5gfapi_dl_tti_pdsch_pdu_allocTimeDomain = -1;
static int hf_5gfapi_dl_tti_request_StartSymbolIndex = -1;
static int hf_5gfapi_dl_tti_request_NrOfSymbols = -1;

static int hf_5gfapi_dl_tti_pdsch_pdu_ptrs = -1;
static int hf_5gfapi_dl_tti_request_PTRSPortIndex = -1;
static int hf_5gfapi_dl_tti_request_PTRSTimeDensity = -1;
static int hf_5gfapi_dl_tti_request_PTRSFreqDensity = -1;
static int hf_5gfapi_dl_tti_request_PTRSReOffset = -1;
static int hf_5gfapi_dl_tti_request_nEpreRatioOfPDSCHToPTRS = -1;

static int hf_5gfapi_dl_tti_pdsch_pdu_txPower = -1;
static int hf_5gfapi_dl_tti_request_powerControlOffset = -1;
static int hf_5gfapi_dl_tti_requst_powerControlOffsetSS = -1;
static int hf_5gfapi_dl_tti_pdsch_pdu_cbgFields = -1;
static int hf_5gfapi_dl_tti_request_IsLastCbPresent = -1;
static int hf_5gfapi_dl_tti_requst_isInlineTbCrc = -1;
static int hf_5gfapi_dl_tti_requst_dlTbCrc = -1;

/*UL_TTI*/
static int hf_5gfapi_UL_tti_Msg_body = -1;
static int hf_5gfapi_Number_of_PDUs = -1;
static int hf_5gfapi_UL_tti_Prach_pdu = -1;
static int hf_5gfapi_UL_tti_beamforming = -1;
static int hf_5gfapi_UL_tti_Pusch_Pdu = -1;
static int hf_5gfapi_UL_tti_Bwp = -1;
static int hf_5gfapi_UL_tti_PUSCH_Info = -1;
static int hf_5gfapi_UL_tti_PRACH_PDU_DMRS = -1;
static int hf_5gfapi_UL_tti_PUSCH_Alloc = -1;
static int hf_5gfapi_UL_tti_Res_Alloc = -1;
static int hf_5gfapi_UL_tti_PUCCH_PDU_Struct = -1;


static int hf_5gfapi_UL_tti_Pucch_Allocation_Fd   = -1;
static int hf_5gfapi_UL_tti_Pucch_Allocation_td = -1;
static int hf_5gfapi_UL_tti_Hopping_Information = -1;
static int hf_5gfapi_UL_tti_PUCCH_PDU_DMRS = -1;


static int hf_nfapi_ul_tti_request_sfn = -1;
static int hf_nfapi_ul_tti_request_slot = -1;
static int hf_nfapi_number_pdus = -1;
static int hf_nfapi_rachpresent = -1;
static int hf_nfapi_nULSCH = -1;
static int hf_nfapi_nULCCH = -1;
static int hf_nfapi_nGroup = -1;
static int hf_nfapi_ul_tti_request_pdu_type = -1;
static int hf_nfapi_pdu_size = -1;
static int hf_nfapi_nUe= -1;
static int hf_nfapi_pduidx = -1;

//Prach Pdu
static int	hf_nfapi_ul_tti_req_prach_pdu_physCellID  = -1;
static int	hf_nfapi_ul_tti_req_prach_pdu_NumPrachOcas = -1;
static int	hf_nfapi_ul_tti_req_prach_pdu_prachFormat = -1;
static int	hf_nfapi_ul_tti_req_prach_pdu_numRa = -1;
static int	hf_nfapi_ul_tti_req_prach_pdu_prachStartSymbol = -1;
static int	hf_nfapi_ul_tti_req_prach_pdu_numCs = -1;

//Beamforming
static int	 hf_nfapi_ul_tti_req_beamforming_numPRGs = -1;
static int	 hf_nfapi_ul_tti_req_beamforming_prgSize = -1;
static int	 hf_nfapi_ul_tti_req_beamforming_digBFInterface = -1;
static int   hf_nfapi_ul_tti_req_beamforming_beamIdx = -1;

//PUSCH PDU
static int  hf_nfapi_ul_tti_req_pusch_pdu_pduBitmap = -1;
static int  hf_nfapi_ul_tti_req_pusch_pdu_RNTI = -1;
static int  hf_nfapi_ul_tti_req_pusch_pdu_Handle = -1;

//BWP:
static int hf_nfapi_ul_tti_req_BWPSize  = -1;     
static int hf_nfapi_ul_tti_req_BWPStart = -1;   
static int hf_nfapi_ul_tti_req_SubcarrierSpacing = -1;  
static int hf_nfapi_ul_tti_req_CyclicPrefix = -1;    

//PUSCH information always included:
static int hf_nfapi_ul_tti_req_pusch_info_targetCodeRate = -1;  
static int hf_nfapi_ul_tti_req_pusch_info_qamModOrder = -1;  
static int hf_nfapi_ul_tti_req_pusch_info_mcsIndex = -1;  
static int hf_nfapi_ul_tti_req_pusch_info_mcsTable = -1;  
static int hf_nfapi_ul_tti_req_pusch_info_TransformPrecoding = -1;  
static int hf_nfapi_ul_tti_req_pusch_info_dataScramblingId = -1; 
static int hf_nfapi_ul_tti_req_pusch_info_nrOfLayers = -1; 

//DMRS:
static int   hf_nfapi_ul_tti_req_dmrs_ulDmrsSymbPos = -1;           
static int   hf_nfapi_ul_tti_req_dmrs_dmrsConfigType = -1;          
static int   hf_nfapi_ul_tti_req_dmrs_ulDmrsScramblingId = -1;          
static int   hf_nfapi_ul_tti_req_dmrs_SCID = -1;                       
static int   hf_nfapi_ul_tti_req_dmrs_numDmrsCdmGrpsNoData = -1;           
static int   hf_nfapi_ul_tti_req_dmrs_dmrsPorts = -1;   

//Pusch Allocation in frequency domain:
static int    hf_nfapi_ul_tti_req_pusch_alloc_resourceAlloc = -1;   
static int    hf_nfapi_ul_tti_req_pusch_alloc_rbBitmap  = -1; 
static int    hf_nfapi_ul_tti_req_pusch_alloc_rbStart = -1;   
static int    hf_nfapi_ul_tti_req_pusch_alloc_rbSize  = -1;  
static int    hf_nfapi_ul_tti_req_pusch_alloc_VRBtoPRBMapping  = -1; 
static int    hf_nfapi_ul_tti_req_pusch_alloc_FrequencyHopping  = -1;  
static int    hf_nfapi_ul_tti_req_pusch_alloc_txDirectCurrentLocation  = -1;  
static int    hf_nfapi_ul_tti_req_pusch_alloc_uplinkFrequencyShift7p5khz  = -1;  

// Resource Allocation in time domain:
static int   hf_nfapi_ul_tti_req_resalloc_StartSymbolIndex  = -1;    
static int   hf_nfapi_ul_tti_req_resalloc_NrOfSymbols  = -1;     

//PUCCH PDU
static int hf_nfapi_RNTI = -1;      
static int hf_nfapi_Handle  = -1;   
static int hf_nfapi_FormatType = -1; 
static int hf_nfapi_multiSlotTxIndicator = -1; 
static int hf_nfapi_pi2Bpsk  = -1;

//Pucch Allocation in frequency domain
static int hf_nfapi_prbStart  = -1; 
static int hf_nfapi_prbSize   = -1; 

//Pucch Allocation in time domain
static int hf_nfapi_StartSymbolIndex  = -1; 
static int hf_nfapi_NrOfSymbols  = -1; 

//Hopping information
static int hf_nfapi_freqHopFlag  = -1;
static int hf_nfapi_secondHopPRB  = -1;
static int hf_nfapi_groupHopFlag  = -1; 
static int hf_nfapi_sequenceHopFlag  = -1;  
static int hf_nfapi_hoppingId  = -1; 
static int hf_nfapi_InitialCyclicShift  = -1; 
static int hf_nfapi_dataScramblingId  = -1; 
static int 	hf_nfapi_TimeDomainOccIdx = -1; 
static int 	hf_nfapi_PreDftOccIdx = -1; 
static int 	hf_nfapi_PreDftOccLen = -1; 

//PUCCH PDU_DMRS
static int hf_nfapi_AddDmrsFlag  = -1; 
static int hf_nfapi_DmrsScramblingId  = -1;  
static int hf_nfapi_DMRScyclicshift  = -1; 
static int hf_nfapi_SRFlag = -1;   
static int hf_nfapi_BitLenHarq  = -1;  
static int hf_nfapi_BitLenCsiPart1  = -1; 
static int hf_nfapi_BitLenCsiPart2  = -1; 

//SRS PDU
static int hf_5gfapi_UL_tti_Srs_pdu = -1;
static int hf_5gfapi_RNTI = -1;   
static int hf_5gfapi_Handle  = -1;  
static int hf_5gfapi_numAntPorts  = -1;   
static int hf_5gfapi_numSymbols  = -1;   
static int hf_5gfapi_numRepetitions = -1;
static int hf_5gfapi_timeStartPosition  = -1;  
static int hf_5gfapi_configIndex  = -1;    
static int hf_5gfapi_sequenceId   = -1;   
static int hf_5gfapi_bandwidthIndex   = -1;   
static int hf_5gfapi_combSize  = -1;   
static int hf_5gfapi_combOffset  = -1;   
static int hf_5gfapi_cyclicShift  = -1;   
static int hf_5gfapi_frequencyPosition  = -1;  
static int hf_5gfapi_frequencyShift  = -1;   
static int hf_5gfapi_frequencyHopping  = -1;   
static int hf_5gfapi_groupOrSequenceHopping = -1;    
static int hf_5gfapi_resourceType  = -1;   
static int hf_5gfapi_Tsrs  = -1;    
static int hf_5gfapi_Toffset  = -1;   



static const value_string message_id_vals[]	= { 
							{ 0x00, "PARAM.request"},
						    { 0x01, "PARAM.response" },
						    { 0x02, "CONFIG.request" },
						    { 0x03, "CONFIG.response" },
						    { 0x04, "START.request" },
						    { 0x05, "STOP.request" },
						    { 0x06, "STOP.indication" },
						    { 0x07, "ERROR.indication" },
						    { 0x80, "DL_TTI.request" },
						    { 0x81, "UL_TTI.request" },
						    { 0x82, "SLOT.indication" },
						    { 0x83, "UL_DCI.request" },
						    { 0x84, "TX_Data.request" },
						    { 0x85, "Rx_Data.indication" },
						    { 0x86, "CRC.indication" },
						    { 0x87, "UCI.indication" },
						    { 0x88, "SRS.indication" },
						    { 0x89, "RACH.indication" },

						    { 0 , NULL },
};

static const value_string nrfapi_error_vals[] = {
	{ 0x0, "MSG_OK" },
	{ 0x1, "MSG_INVALID_STATE" },
	
	{ 0, NULL },
};
#if 0
static const value_string ul_dci_pdu_types_vals[] = {
	{ 0, "PDCCH PDU" },
};
#endif

static const value_string nfapi_ul_tti_request_pdu_type_vals[] = {
	{ 0, "PRACH_PDU" },
	{ 1, "PUSCH_PDU" },
	{ 2, "PUCCH_PDU" },
	{ 3, "SRS_PDU" },
	
	{ 0, NULL }
}; 

static const value_string nrfapi_cceRegMapping_types_vals[] = {
	{ 0, "Non-Interleaved" },
	{ 1, "Interleaved" },
};

static const value_string dl_tti_pdu_type_vals[]	= { 
							{ 0x00, "PDCCH_PDU"},
						    { 0x01, "PDSCH_PDU" },
						    { 0x02, "CSI_RS_PDU" },
						    { 0x03, "SSB_PDU" },

						    { 0 , NULL },
};

static const value_string dl_tti_ssb_pdu_beta_pss[]  = { 
							{ 0x00, "0 dB"},
							{ 0x01, "3 dB" },

							{ 0 , NULL },
};

static const value_string dl_tti_csi_rs_type[]  = { 
							{ 0x00, "TRS" },
							{ 0x01, "CSI_RS_NZP"},
							{ 0x02, "CSI_RS_ZP"},

							{ 0 , NULL },
};

static const value_string dl_tti_csi_rs_cmd_type[]  = { 
							{ 0x00, "NO_CDM" },
							{ 0x01, "FD_CDM2"},
							{ 0x02, "CMD4_FD2_TD2"},
							{ 0x03, "CMD8_FD2_TD4"},

							{ 0 , NULL },
};

static const value_string dl_tti_csi_rs_tx_power_control_offset_ss[]  = { 
							{ 0x00, "-3dB" },
							{ 0x01, "0dB"},
							{ 0x02, "3dB"},
							{ 0x03, "6dB"},

							{ 0 , NULL },
};

static const value_string dl_tti_cyclicPrefix_vals[]	= { 
							{ 0x00, "Normal"},
						    { 0x01, "Extended" },
};

static const value_string dl_tti_mcsTable_vals[]	= { 
							{ 0x00, "notqam256"},
						    { 0x01, "qam256" },
							{ 0x02, "qam64LowSE" },
};

static const value_string dl_tti_dlDmrsSymbPos_vals[]	= { 
							{ 0x00, "no DMRS"},
						    { 0x01, "DMRS" },
};

static const value_string dl_tti_dmrsConfigType_vals[]	= { 
							{ 0x00, "type 1"},
						    { 0x01, "type 2" },
};

static const value_string dl_tti_dmrsPorts_vals[]	= { 
							{ 0x00, "DMRS port not used"},
						    { 0x01, "DMRS port used" },
};

static const value_string dl_tti_resourceAlloc_vals[]	= { 
							{ 0x00, "Type 0"},
						    { 0x01, "Type 1" },
};

static const value_string dl_tti_VRBtoPRBMapping_vals[]	= { 
							{ 0x00, "non-interleaved"},
						    { 0x01, "interleaved with RB size 2" },
							{ 0x02, "Interleaved with RB size 4" },
};

static const value_string dl_tti_PTRSPortIndex_vals[]	= { 
							{ 0x00, "PTRS port not used"},
						    { 0x01, "PTRS port used" },
};

static const value_string dl_tti_PTRSTimeDensity_vals[]	= { 
							{ 0x00, "1"},
						    { 0x01, "2" },
							{ 0x02, "4" },
};

static const value_string dl_tti_PTRSFreqDensity_vals[]	= { 
							{ 0x00, "2"},
						    { 0x01, "4" },
};


/*Utility Functions*/
static guint8 proto_tree_add_uint8(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, char* units)
{
	guint8 value = tvb_get_guint8(tvb, *offset);
	proto_item * item =  proto_tree_add_item(tree, hfindex, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	if (units != NULL)
	{
		proto_item_append_text(item, " ");
		proto_item_append_text(item, units);
	}

	*offset += 1;

	return value;
}

static guint16 proto_tree_add_uint16(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, char* units)
{
	guint16 value = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
	proto_item * item =  proto_tree_add_item(tree, hfindex, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	if (units != NULL)
	{
		proto_item_append_text(item, " ");
		proto_item_append_text(item, units);
	}

	*offset += 2;

	return value;
}

static void proto_tree_add_uint32(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, char* units)
{
	proto_item * item = proto_tree_add_item(tree, hfindex, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

	if (units != NULL)
	{
		proto_item_append_text(item, " ");
		proto_item_append_text(item, units);
	}

	*offset += 4;
}

/* FAPI P5-P7 General Header Dissection functions */
static int dissect_p7p5_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, guint* offset)
{
	proto_item *p7_p5_header_ti = proto_tree_add_string_format(tree, hf_5gfapi_p7_p5_message_header, tvb, *offset, NR_FAPI_HEADER_LENGTH, "", "P7 P5 JIO Header");
	proto_tree *p7_p5_header_tree = proto_item_add_subtree(p7_p5_header_ti, ett_5gfapi_p7_p5_message_header);

	proto_tree_add_uint8(p7_p5_header_tree, hf_5gfapi_p7_p5_message_header_num_of_msgs, tvb, offset, 0);
	proto_tree_add_uint8(p7_p5_header_tree, hf_5gfapi_p7_p5_message_header_phy_id, tvb, offset, 0);
	proto_tree_add_uint16(p7_p5_header_tree, hf_5gfapi_p7_p5_message_header_message_id, tvb, offset, 0);
	proto_tree_add_uint32(p7_p5_header_tree, hf_5gfapi_p7_p5_message_header_message_length, tvb, offset, "bytes");

	return 0;
}

static int dissectDlTtiPdschPduBwp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset)
{
	proto_item *dl_tti_ti_pdsch_pdu_bwp = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_pdsch_pdu_bwp, tvb, *offset, 6, "", "BWP");
	proto_tree *dl_tti_pdsch_pdu_bwp_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu_bwp, ett_5gfapi_dl_tti_pdsch_pdu_bwp);

	proto_tree_add_uint16(dl_tti_pdsch_pdu_bwp_tree, hf_5gfapi_dl_tti_request_bwp_size, tvb, offset, 0);
	proto_tree_add_uint16(dl_tti_pdsch_pdu_bwp_tree, hf_5gfapi_dl_tti_request_bwp_start, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_bwp_tree, hf_5gfapi_dl_tti_request_sub_carrier_spacing, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_bwp_tree, hf_5gfapi_dl_tti_request_cyclic_prefix, tvb, offset, 0);

	return 0;
}

static int dissectDlTtiPdschPduCodewordInfo(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset)
{
    proto_item *dl_tti_ti_pdsch_pdu_Codeword_info = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_pdsch_pdu_Codeword_info, tvb, *offset, 1, "", "Codeword information");
	proto_tree *dl_tti_pdsch_pdu_Codeword_info_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu_Codeword_info, ett_5gfapi_dl_tti_pdsch_pdu_Codeword_info);

	guint8 nrOfCodewords = proto_tree_add_uint8(dl_tti_pdsch_pdu_Codeword_info_tree, hf_5gfapi_dl_tti_request_nrOfCodewords, tvb, offset, 0);

	for (int i = 0; i < nrOfCodewords; i++)
	{
		proto_item *dl_tti_ti_pdsch_pdu_Codeword = proto_tree_add_string_format(dl_tti_pdsch_pdu_Codeword_info_tree, hf_5gfapi_dl_tti_pdsch_pdu_Codeword, tvb, *offset, 12, "", "Codeword");
	    proto_tree *dl_tti_pdsch_pdu_Codeword_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu_Codeword, ett_5gfapi_dl_tti_pdsch_pdu_Codeword);

		proto_tree_add_uint16(dl_tti_pdsch_pdu_Codeword_tree, hf_5gfapi_dl_tti_request_targetCodeRate, tvb, offset, 0);
		proto_tree_add_uint8(dl_tti_pdsch_pdu_Codeword_tree, hf_5gfapi_dl_tti_request_qamModOrder, tvb, offset, 0);
		proto_tree_add_uint8(dl_tti_pdsch_pdu_Codeword_tree, hf_5gfapi_dl_tti_request_mcsIndex, tvb, offset, 0);
		proto_tree_add_uint8(dl_tti_pdsch_pdu_Codeword_tree, hf_5gfapi_dl_tti_request_mcsTable, tvb, offset, 0);
		proto_tree_add_uint8(dl_tti_pdsch_pdu_Codeword_tree, hf_5gfapi_dl_tti_request_rvIndex, tvb, offset, 0);
		proto_tree_add_uint32(dl_tti_pdsch_pdu_Codeword_tree, hf_5gfapi_dl_tti_request_tbSize, tvb, offset, 0);

	}
	return 0;

}

static int dissectDlTtiPdschPduDmrs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset)
{
	proto_item *dl_tti_ti_pdsch_pdu_dmrs = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_pdsch_pdu_dmrs, tvb, *offset, 9, "", "DMRS");
	proto_tree *dl_tti_pdsch_pdu_dmrs_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu_dmrs, ett_5gfapi_dl_tti_pdsch_pdu_dmrs);

	proto_tree_add_uint16(dl_tti_pdsch_pdu_dmrs_tree, hf_5gfapi_dl_tti_request_dlDmrsSymbPos, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_dmrs_tree, hf_5gfapi_dl_tti_request_dmrsConfigType, tvb, offset, 0);
	proto_tree_add_uint16(dl_tti_pdsch_pdu_dmrs_tree, hf_5gfapi_dl_tti_request_dlDmrsScramblingId, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_dmrs_tree, hf_5gfapi_dl_tti_request_SCID, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_dmrs_tree, hf_5gfapi_dl_tti_request_numDmrsCdmGrpsNoData, tvb, offset, 0);
	proto_tree_add_uint16(dl_tti_pdsch_pdu_dmrs_tree, hf_5gfapi_dl_tti_request_dmrsPorts, tvb, offset, 0);

	return 0;
}

static int dissectDlTtiPdschPduAllocFreqDomain(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset)
{
	proto_item *dl_tti_ti_pdsch_pdu_allocFreqDomain = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_pdsch_pdu_allocFreqDomain, tvb, *offset, 42, "", "Pdsch Allocation in Frequency Domain");
	proto_tree *dl_tti_pdsch_pdu_allocFreqDomain_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu_allocFreqDomain, ett_5gfapi_dl_tti_pdsch_pdu_allocFreqDomain);

	proto_tree_add_uint8(dl_tti_pdsch_pdu_allocFreqDomain_tree, hf_5gfapi_dl_tti_request_resourceAlloc, tvb, offset, 0);

	for (int i = 0; i < 36 ; i++)
	{
		proto_tree_add_uint8(dl_tti_pdsch_pdu_allocFreqDomain_tree, hf_5gfapi_dl_tti_request_rbBitmap, tvb, offset, 0);
	}
	proto_tree_add_uint16(dl_tti_pdsch_pdu_allocFreqDomain_tree, hf_5gfapi_dl_tti_request_rbStart, tvb, offset, 0);
	proto_tree_add_uint16(dl_tti_pdsch_pdu_allocFreqDomain_tree, hf_5gfapi_dl_tti_request_rbSize, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_allocFreqDomain_tree, hf_5gfapi_dl_tti_request_VRBtoPRBMapping, tvb, offset, 0);
	//proto_tree_add_uint16(dl_tti_pdsch_pdu_allocFreqDomain_tree, hf_5gfapi_dl_tti_request_dmrsPorts, tvb, offset, 0);

	return 0;
}

static int dissectDlTtiPdschPduAllocTimeDomain(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset)
{
	proto_item *dl_tti_ti_pdsch_pdu_allocTimeDomain = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_pdsch_pdu_allocTimeDomain, tvb, *offset, 2, "", "Pdsch Allocation in Time Domain");
	proto_tree *dl_tti_pdsch_pdu_allocTimeDomain_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu_allocTimeDomain, ett_5gfapi_dl_tti_pdsch_pdu_allocTimeDomain);

	proto_tree_add_uint8(dl_tti_pdsch_pdu_allocTimeDomain_tree, hf_5gfapi_dl_tti_request_StartSymbolIndex, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_allocTimeDomain_tree, hf_5gfapi_dl_tti_request_NrOfSymbols, tvb, offset, 0);

	return 0;
}

static int dissectDlTtiPdschPduPtrs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset)
{
	proto_item *dl_tti_ti_pdsch_pdu_ptrs = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_pdsch_pdu_ptrs, tvb, *offset, 5, "", "PTRS");
	proto_tree *dl_tti_pdsch_pdu_ptrs_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu_ptrs, ett_5gfapi_dl_tti_pdsch_pdu_ptrs);

	proto_tree_add_uint8(dl_tti_pdsch_pdu_ptrs_tree, hf_5gfapi_dl_tti_request_PTRSPortIndex, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_ptrs_tree, hf_5gfapi_dl_tti_request_PTRSTimeDensity, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_ptrs_tree, hf_5gfapi_dl_tti_request_PTRSFreqDensity, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_ptrs_tree, hf_5gfapi_dl_tti_request_PTRSReOffset, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_ptrs_tree, hf_5gfapi_dl_tti_request_nEpreRatioOfPDSCHToPTRS, tvb, offset, 0);
	//proto_tree_add_uint16(dl_tti_pdsch_pdu_allocFreqDomain_tree, hf_5gfapi_dl_tti_request_dmrsPorts, tvb, offset, 0);

	return 0;
}

static int dissect_precoding_beamforming_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, guint* offset, guint16 msg_len)
{
	guint16 i = 0;
	guint16 j = 0;
	proto_item *beamforming_info_ti = proto_tree_add_string_format(tree, hf_5gfapi_dl_dci_beamforming_info, tvb, *offset, msg_len, "", "Precoding and Beamforming");
	proto_tree *beamforming_info_tree = proto_item_add_subtree(beamforming_info_ti, ett_5gfapi_dl_dci_beamforming_info);

	guint16 numPrg = proto_tree_add_uint16(beamforming_info_tree, hf_5gfapi_numPRGs, tvb, offset, 0);
	proto_tree_add_uint16(beamforming_info_tree, hf_5gfapi_prgSize, tvb, offset, 0);
	guint16 num_digBFInterfaces = proto_tree_add_uint8(beamforming_info_tree, hf_5gfapi_digBFInterfaces, tvb, offset, 0);

	for(i = 0; i < numPrg; i++)
	{
		proto_tree_add_uint16(beamforming_info_tree, hf_5gfapi_PMidx, tvb, offset, 0);

		for(j=0; j<num_digBFInterfaces; j++)
		{
			proto_tree_add_uint16(beamforming_info_tree, hf_5gfapi_beamIdx, tvb, offset, 0);
		}
	}
	return 0;
}

static int dissectDlTtiPdschPduTxPowerInfo(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset)
{
	proto_item *dl_tti_ti_pdsch_pdu_txPower = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_pdsch_pdu_txPower, tvb, *offset, 2, "", "Tx Power Info");
	proto_tree *dl_tti_pdsch_pdu_txPower_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu_txPower, ett_5gfapi_dl_tti_pdsch_pdu_txPower);

	proto_tree_add_uint8(dl_tti_pdsch_pdu_txPower_tree, hf_5gfapi_dl_tti_request_powerControlOffset, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_txPower_tree, hf_5gfapi_dl_tti_requst_powerControlOffsetSS, tvb, offset, 0);

	return 0;
}

static int dissectDlTtiPdschPduCbgFields(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset)
{
	proto_item *dl_tti_ti_pdsch_pdu_cbgFields = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_pdsch_pdu_cbgFields, tvb, *offset, 6, "", "CBG Fields");
	proto_tree *dl_tti_pdsch_pdu_cbgFields_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu_cbgFields, ett_5gfapi_dl_tti_pdsch_pdu_cbgFields);

	proto_tree_add_uint8(dl_tti_pdsch_pdu_cbgFields_tree, hf_5gfapi_dl_tti_request_IsLastCbPresent, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_cbgFields_tree, hf_5gfapi_dl_tti_requst_isInlineTbCrc, tvb, offset, 0);
    proto_tree_add_uint32(dl_tti_pdsch_pdu_cbgFields_tree, hf_5gfapi_dl_tti_requst_dlTbCrc, tvb, offset, 0);
	
	return 0;
}

static int dissectDlTtiPdschPdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset)
{
	proto_item *dl_tti_ti_pdsch_pdu = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_pdsch_pdu, tvb, *offset, msgLen, "", "PDSCH PDU");
	proto_tree *dl_tti_pdsch_pdu_tree = proto_item_add_subtree(dl_tti_ti_pdsch_pdu, ett_5gfapi_dl_tti_pdsch_pdu);

	proto_tree_add_uint16(dl_tti_pdsch_pdu_tree, hf_5gfapi_dl_tti_request_pduBitmap, tvb, offset, 0);
	proto_tree_add_uint16(dl_tti_pdsch_pdu_tree, hf_5gfapi_dl_tti_request_rnti, tvb, offset, 0);
	proto_tree_add_uint16(dl_tti_pdsch_pdu_tree, hf_5gfapi_dl_tti_request_pdu_index, tvb, offset, 0);

	dissectDlTtiPdschPduBwp(tvb, pinfo, dl_tti_pdsch_pdu_tree, msgLen, data, offset);

	dissectDlTtiPdschPduCodewordInfo(tvb, pinfo, dl_tti_pdsch_pdu_tree, msgLen, data, offset);

	proto_tree_add_uint16(dl_tti_pdsch_pdu_tree, hf_5gfapi_dl_tti_request_dataScramblingId, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_tree, hf_5gfapi_dl_tti_request_nrOfLayers, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_tree, hf_5gfapi_dl_tti_request_transmissionScheme, tvb, offset, 0);
	proto_tree_add_uint8(dl_tti_pdsch_pdu_tree, hf_5gfapi_dl_tti_request_refPoint, tvb, offset, 0);

	dissectDlTtiPdschPduDmrs(tvb, pinfo, dl_tti_pdsch_pdu_tree, msgLen, data, offset);

	dissectDlTtiPdschPduAllocFreqDomain(tvb, pinfo, dl_tti_pdsch_pdu_tree, msgLen, data, offset);

	dissectDlTtiPdschPduAllocTimeDomain(tvb, pinfo, dl_tti_pdsch_pdu_tree, msgLen, data, offset);

	dissectDlTtiPdschPduPtrs(tvb, pinfo, dl_tti_pdsch_pdu_tree, msgLen, data, offset);

	dissect_precoding_beamforming_pdu(tvb, pinfo, dl_tti_pdsch_pdu_tree, data, offset, 4);

	dissectDlTtiPdschPduTxPowerInfo(tvb, pinfo, dl_tti_pdsch_pdu_tree, msgLen, data, offset);

	dissectDlTtiPdschPduCbgFields(tvb, pinfo, dl_tti_pdsch_pdu_tree, msgLen, data, offset);

	return 0;
}

static int dissect_pdcch_pdu_struct(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, guint* offset, guint16 msg_len)
{
	guint16 i = 0;
	guint16 j = 0;
	guint16 num_dlDci = 0;

	proto_item *pdcch_pdu_bwp_ti = proto_tree_add_string_format(tree, hf_5gfapi_ul_dci_pdcch_pdu_bwp, tvb, *offset, 6, "", "pdcchPdu->BWP");
	proto_tree *pdcch_pdu_bwp_tree = proto_item_add_subtree(pdcch_pdu_bwp_ti, ett_5gfapi_ul_dci_pdcch_pdu_bwp);

	proto_tree_add_uint16(pdcch_pdu_bwp_tree, hf_5gfapi_bwp_size, tvb, offset, 0);
	proto_tree_add_uint16(pdcch_pdu_bwp_tree, hf_5gfapi_bwp_start, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_pdu_bwp_tree, hf_5gfapi_subcarrier_spacing, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_pdu_bwp_tree, hf_5gfapi_cyclic_prefix, tvb, offset, 0);
	
	proto_item *pdcch_pdu_coreset_ti = proto_tree_add_string_format(tree, hf_5gfapi_ul_dci_pdcch_pdu_coreset, tvb, *offset, msg_len-6, "", "pdcchPdu->Coreset");
	proto_tree *pdcch_pdu_coreset_tree = proto_item_add_subtree(pdcch_pdu_coreset_ti, ett_5gfapi_ul_dci_pdcch_pdu_coreset);

	proto_tree_add_uint8(pdcch_pdu_coreset_tree, hf_5gfapi_StartSymbolIndex, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_pdu_coreset_tree, hf_5gfapi_DurationSymbols, tvb, offset, 0);
	for(i = 0; i < 6; i++)
	{
		proto_tree_add_uint8(pdcch_pdu_coreset_tree, hf_5gfapi_FreqDomainResource, tvb, offset, 0);
	}
	proto_tree_add_uint8(pdcch_pdu_coreset_tree, hf_5gfapi_CceRegMappingType, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_pdu_coreset_tree, hf_5gfapi_RegBundleSize, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_pdu_coreset_tree, hf_5gfapi_InterleaverSize, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_pdu_coreset_tree, hf_5gfapi_CoreSetType, tvb, offset, 0);
	proto_tree_add_uint16(pdcch_pdu_coreset_tree, hf_5gfapi_ShiftIndex, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_pdu_coreset_tree, hf_5gfapi_precoderGranularity, tvb, offset, 0);

	num_dlDci = proto_tree_add_uint16(tree, hf_5gfapi_numDlDci, tvb, offset, 0);
    msg_len = msg_len-23;
	for(i = 0; i < num_dlDci; i++)
	{
		proto_item *dl_dci_ti = proto_tree_add_string_format(tree, hf_5gfapi_dl_dci_structure, tvb, *offset, msg_len, "", "DL_DCI_PDU[%d]", i);
		proto_tree *dl_dci_tree = proto_item_add_subtree(dl_dci_ti, ett_5gfapi_dl_dci_structure);

		proto_tree_add_uint16(dl_dci_tree, hf_5gfapi_rnti, tvb, offset, 0);
		proto_tree_add_uint16(dl_dci_tree, hf_5gfapi_scramblingId, tvb, offset, 0);
		proto_tree_add_uint16(dl_dci_tree, hf_5gfapi_ScramblingRNTI, tvb, offset, 0);
		proto_tree_add_uint8(dl_dci_tree, hf_5gfapi_CceIndex, tvb, offset, 0);
		proto_tree_add_uint8(dl_dci_tree, hf_5gfapi_AggregationLevel, tvb, offset, 0);

		guint16 numPrg = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
		guint8 num_digBFInterfaces = tvb_get_guint8(tvb, *offset+4);
		
		dissect_precoding_beamforming_pdu(tvb, pinfo, dl_dci_tree, data, offset, msg_len-8);

		msg_len = msg_len-8-((2*num_digBFInterfaces*numPrg)+(2*numPrg));
		
		proto_item *tx_pwr_info_ti = proto_tree_add_string_format(dl_dci_tree, hf_5gfapi_dl_dci_tx_pwr_info, tvb, *offset, msg_len, "", "Tx Power Info");
		proto_tree *tx_pwr_info_tree = proto_item_add_subtree(tx_pwr_info_ti, ett_5gfapi_dl_dci_tx_pwr_info);
		
		proto_tree_add_uint8(tx_pwr_info_tree, hf_5gfapi_beta_pdcch_1_0, tvb, offset, 0);
		proto_tree_add_uint8(tx_pwr_info_tree, hf_5gfapi_powerControlOffsetSS, tvb, offset, 0);

		guint8 payloadSizeBits = proto_tree_add_uint8(dl_dci_tree, hf_5gfapi_PayloadSizeBits, tvb, offset, "bits");
		guint8 payloadSizeBytes = ((payloadSizeBits+7)/8); /*CEIL(payloadSizeBits/8)*/

		for(j=0; j<payloadSizeBytes+1; j++)
		{
			proto_tree_add_uint8(dl_dci_tree, hf_5gfapi_Payload, tvb, offset, 0);
		}
		msg_len = msg_len-3-(1*payloadSizeBytes);
	}
	
	return 0;
}

/* SSB Dissection*/
static int dissect_pdcch_ssb_pbch_pdu_structure(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, guint* offset, guint16 msg_len)
{
	proto_item *pdcch_ssb_pdu_mib_ti = proto_tree_add_string_format(tree, hf_5gfapi_pdcch_pdu_mib, tvb, *offset, 8, "", "PDCCH_MIB_PDU.info");
	proto_tree *pdcch_ssb_pdu_mib_tree = proto_item_add_subtree(pdcch_ssb_pdu_mib_ti, ett_5gfapi_dl_tti_request_pdu_info);

	proto_tree_add_uint32(pdcch_ssb_pdu_mib_tree, hf_5gfapi_pdcch_pdu_mib_bch_payload, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_ssb_pdu_mib_tree, hf_5gfapi_pdcch_pdu_mib_dmrs_type_a_psition, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_ssb_pdu_mib_tree, hf_5gfapi_pdcch_pdu_mib_pdcch_config_sib1, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_ssb_pdu_mib_tree, hf_5gfapi_pdcch_pdu_mib_cell_barred, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_ssb_pdu_mib_tree, hf_5gfapi_pdcch_pdu_mib_intra_freq_reselection, tvb, offset, 0);

	return 0;
	
}
static int dissect_pdcch_ssb_mib_pdu_structure(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, guint* offset, guint16 msg_len)
{
	proto_item * pdcch_ssb_pdu_ti = proto_tree_add_string_format(tree, hf_5gfapi_pdcch_pdu_ssb, tvb, *offset, 8, "", "PDCCH_SSB_PBCH_PDU.info");
	proto_tree * pdcch_ssb_pdu_tree = proto_item_add_subtree(pdcch_ssb_pdu_ti, ett_5gfapi_dl_tti_request_pdu_info);

	proto_tree_add_uint16(pdcch_ssb_pdu_tree, hf_5gfapi_pdcch_pdu_ssb_phy_cell_id, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_ssb_pdu_tree, hf_5gfapi_pdcch_pdu_ssb_beta_pss, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_ssb_pdu_tree, hf_5gfapi_pdcch_pdu_ssb_block_index, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_ssb_pdu_tree, hf_5gfapi_pdcch_pdu_ssb_subcarrier_offset, tvb, offset, 0);
	proto_tree_add_uint16(pdcch_ssb_pdu_tree, hf_5gfapi_pdcch_pdu_ssb_offset_point_a, tvb, offset, 0);
	proto_tree_add_uint8(pdcch_ssb_pdu_tree, hf_5gfapi_pdcch_pdu_ssb_bch_payload_flag, tvb, offset, 0);

	return 0;
}

/* CSI RS */
static int dissect_pdcch_csi_rs_bwp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, guint* offset, guint16 msg_len)
{
	proto_item * csi_rs_bwp_pdu_ti = proto_tree_add_string_format(tree, hf_5gfapi_csi_rs_bwp_pdu, tvb, *offset, 6, "", "CSI_RS_BWP.info");
	proto_tree * csi_rs_bwp_pdu_tree = proto_item_add_subtree(csi_rs_bwp_pdu_ti, ett_5gfapi_dl_tti_request_pdu_info);

	proto_tree_add_uint16(csi_rs_bwp_pdu_tree, hf_5gfapi_csi_rs_bwp_pdu_size, tvb, offset, 0);	
	proto_tree_add_uint16(csi_rs_bwp_pdu_tree, hf_5gfapi_csi_rs_bwp_pdu_start, tvb, offset, 0);
	proto_tree_add_uint8(csi_rs_bwp_pdu_tree, hf_5gfapi_csi_rs_bwp_pdu_subcarrier_spacing, tvb, offset, 0);
	proto_tree_add_uint8(csi_rs_bwp_pdu_tree, hf_5gfapi_csi_rs_bwp_pdu_cyclic_prefix, tvb, offset, 0);

	return 0;
}

static int dissect_pdcch_csi_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, guint* offset, guint16 msg_len)
{
	proto_item * csi_rs_pdu_ti = proto_tree_add_string_format(tree, hf_5gfapi_csi_rs_pdu, tvb, *offset, 14, "", "CSI_RS.info");
	proto_tree * csi_rs_pdu_tree = proto_item_add_subtree(csi_rs_pdu_ti, ett_5gfapi_dl_tti_request_pdu_info);

	proto_tree_add_uint16(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_start_rb, tvb, offset, 0);	
	proto_tree_add_uint16(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_nr_of_rbs, tvb, offset, 0);
	proto_tree_add_uint8(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_csi_type, tvb, offset, 0);
	proto_tree_add_uint8(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_row, tvb, offset, 0);
	proto_tree_add_uint16(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_freq_domain, tvb, offset, 0);
	proto_tree_add_uint8(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_symbL0, tvb, offset, 0);
	proto_tree_add_uint8(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_symbl1, tvb, offset, 0);
	proto_tree_add_uint8(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_cdm_type, tvb, offset, 0);
	proto_tree_add_uint8(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_freq_density, tvb, offset, 0);
	proto_tree_add_uint16(csi_rs_pdu_tree, hf_5gfapi_csi_rs_pdu_scramb_id, tvb, offset, 0);

	return 0;
}

static int dissect_pdcch_tx_power_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, guint* offset, guint16 msg_len)
{
	proto_item * csi_rs_tx_power_ti = proto_tree_add_string_format(tree, hf_5gfapi_csi_rs_pdu_tx_power_info, tvb, *offset, 2, "", "TX_POWER.info");
	proto_tree * csi_rs_tx_power_tree = proto_item_add_subtree(csi_rs_tx_power_ti, ett_5gfapi_dl_tti_request_pdu_info);

	proto_tree_add_uint8(csi_rs_tx_power_tree, hf_5gfapi_csi_rs_pdu_tx_power_info_power_control_offset, tvb, offset, 0);
	proto_tree_add_uint8(csi_rs_tx_power_tree, hf_5gfapi_csi_rs_pdu_tx_power_info_power_control_offsetSS, tvb, offset, 0);

	return 0;
}


/* FAPI P5-P7 General Header Dissection functions */
static int dissectDlTtiReqPduInfo(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset, guint8 nGroup)
{
	switch (pduType)
	{
		case 0 : /*PDCCH PDU*/
		{
			dissect_pdcch_pdu_struct(tvb, pinfo , tree, data, offset, msgLen);
 			break;
		}
		case 1 : /*PDSCH PDU*/
		{
			dissectDlTtiPdschPdu (tvb, pinfo, tree, msgLen, data, offset);
			//*offset += 90;
			break;
		}
		case 2 : /*CSI-RS PDU*/
		{
			dissect_pdcch_csi_rs_bwp(tvb, pinfo, tree, data, offset, msgLen);
			msgLen = msgLen - 6;
			dissect_pdcch_csi_rs(tvb, pinfo, tree, data, offset, msgLen);
			msgLen = msgLen - 14;
			dissect_pdcch_tx_power_info(tvb, pinfo, tree, data, offset, msgLen);
			msgLen = msgLen - 2;
			dissect_precoding_beamforming_pdu(tvb, pinfo, tree, data, offset, msgLen);
			break;
		}
		case 3 : /*SSB-PDU*/
		{
			dissect_pdcch_ssb_pbch_pdu_structure(tvb, pinfo , tree, data, offset, msgLen);
			msgLen = msgLen - 8;
			dissect_pdcch_ssb_mib_pdu_structure(tvb, pinfo , tree, data, offset, msgLen);
			msgLen = msgLen - 8;
			dissect_precoding_beamforming_pdu(tvb, pinfo, tree, data, offset, msgLen);
			break;
		}
		default :
		{

			//printf ("\n wrong PDU \n");
			break;
		}
	}

	return 0;
}

/* FAPI DL TTI Dissection functions */
static int dissectDlTtiReq(tvbuff_t *tvb, packet_info *pinfo , proto_tree *tree, guint32 msgLen, void* data , guint* offset)
{
    guint8 noPdus = 0;
	guint8 nGroup = 0;
	guint16 pduType = 0;

	proto_item *dl_tti_ti = proto_tree_add_string_format(tree, hf_5gfapi_dl_tti_request, tvb, *offset, msgLen, "", "DL_TTI.request");
	proto_tree *dl_tti_tree = proto_item_add_subtree(dl_tti_ti, ett_5gfapi_dl_tti_request);

	proto_tree_add_uint16(dl_tti_tree, hf_5gfapi_sfn, tvb, offset, 0);
	proto_tree_add_uint16(dl_tti_tree, hf_5gfapi_slot, tvb, offset, 0);
	noPdus = proto_tree_add_uint8(dl_tti_tree, hf_5gfapi_num_pdus, tvb, offset, 0);
	nGroup = proto_tree_add_uint8(dl_tti_tree, hf_5gfapi_num_group, tvb, offset, 0);

	for (int i = 0; i < noPdus; i++)
	{
		guint16 pduSize = tvb_get_guint16(tvb, *offset+2, ENC_LITTLE_ENDIAN);

		proto_item *dl_tti_pdu_ti = proto_tree_add_string_format(dl_tti_tree, hf_5gfapi_dl_tti_request_pdu_info, tvb, *offset, pduSize, "", "PDU.info");
		proto_tree *dl_tti_pdu_tree = proto_item_add_subtree(dl_tti_pdu_ti, ett_5gfapi_dl_tti_request_pdu_info);

		pduType = proto_tree_add_uint16(dl_tti_pdu_tree, hf_5gfapi_pdu_type, tvb, offset, 0);
		proto_tree_add_uint16(dl_tti_pdu_tree, hf_5gfapi_pdu_size, tvb, offset, 0);

		dissectDlTtiReqPduInfo (tvb, pinfo, dl_tti_pdu_tree, pduType, pduSize - 4, data, offset, nGroup);

	}

	return 0;
}

static int dissect_ul_dci_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_, guint* offset, guint32 msg_len)
{
	int i = 0;
	guint8 num_pdus = 0;
#if 0
	guint16 n_pdu_size = 0;
    guint8 num_pdus = tvb_get_guint8(tvb, *offset+4);
	
	for(i=0; i<num_pdus; i++)
	{
		n_pdu_size += tvb_get_guint16(tvb, *offset+5+(n_pdu_size)+2, ENC_LITTLE_ENDIAN);
	}
#endif
	proto_item *ul_dci_ti = proto_tree_add_string_format(tree, hf_5gfapi_ul_dci_message_body, tvb, *offset, msg_len, "", "UL DCI Message Body");
	proto_tree *ul_dci_tree = proto_item_add_subtree(ul_dci_ti, ett_5gfapi_ul_dci_message_body);

	proto_tree_add_uint16(ul_dci_tree, hf_5gfapi_sfn, tvb, offset, 0);
    proto_tree_add_uint16(ul_dci_tree, hf_5gfapi_slot, tvb, offset, 0);
	num_pdus = proto_tree_add_uint8(ul_dci_tree, hf_5gfapi_num_pdcch_pdu, tvb, offset, 0);
	
	if (num_pdus > 0)
	{
		proto_item *list_ti = proto_tree_add_string_format(ul_dci_tree, hf_5gfapi_pdu_list, tvb, *offset, msg_len, "", "PDU List");
		proto_tree *list_tree = proto_item_add_subtree(list_ti, ett_5gfapi_pdu_list);

		for(i = 0; i < num_pdus; i++ )
		{
			guint16 pdu_size = tvb_get_guint16(tvb, *offset+2, ENC_LITTLE_ENDIAN);
			
			proto_item *item_ti = proto_tree_add_string_format(list_tree, hf_5gfapi_pdu_idx, tvb, *offset, pdu_size, "", "PDU[%d]", i);
			proto_tree *item_tree = proto_item_add_subtree(item_ti, ett_5gfapi_pdu_idx);
			
			proto_tree_add_uint16(item_tree, hf_5gfapi_pdu_type, tvb, offset, 0);
			proto_tree_add_uint16(item_tree, hf_5gfapi_pdu_size, tvb, offset, "bytes");

			proto_item *sub_item_ti = proto_tree_add_string_format(item_tree, hf_5gfapi_pdcch_pdu_config, tvb, *offset, pdu_size-4, "", "pdcch_pdu_config[%d]", i);
			proto_tree *sub_item_tree = proto_item_add_subtree(sub_item_ti, ett_5gfapi_pdcch_pdu_config);

			dissect_pdcch_pdu_struct(tvb, pinfo, sub_item_tree, data, offset, pdu_size-4);
			
		}
	}
	return 0;
}

/*** UL_TTI.Request Dissection Functions Start***/
static int dissect_PRACH_PDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,  guint16 msgLen, void* data _U_, guint* offset, guint16 pduType)
{
   
	guint16 msgLen1 = 8;
	proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_Prach_pdu, tvb, *offset, msgLen1, "", "PRACH PDU Parameters");
	proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_Prach_pdu);

	proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_prach_pdu_physCellID, tvb, offset, 0);  
    proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_prach_pdu_NumPrachOcas, tvb, offset, 0); 
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_prach_pdu_prachFormat, tvb, offset, 0); 
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_prach_pdu_numRa, tvb, offset, 0); 
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_prach_pdu_prachStartSymbol, tvb, offset, 0); 
	proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_prach_pdu_numCs, tvb, offset, 0);  

    return 0;

}
static int dissect_Beamforming(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,  guint16 msgLen, void* data _U_, guint* offset, guint16 pduType)
{
	
    guint16 num_PRGs = 0;
    guint8  digBFInterface = 0;

    proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_beamforming, tvb, *offset,msgLen, "", "Beamforming Parameters ");
    proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_beamforming);

	proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_beamforming_numPRGs, tvb, offset, 0);  
    proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_beamforming_prgSize, tvb, offset, 0);
    proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_beamforming_digBFInterface, tvb, offset, 0); 

	for(int i=0; i < num_PRGs; i++)
	{
		for(int j=0; j < digBFInterface; j++)
		{

			proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_beamforming_beamIdx, tvb, offset, 0);  

		}
	}

    return 0;

}

static int dissect_PUSCH_PDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset, guint16 pduType)
{
	proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_Pusch_Pdu, tvb, *offset,8, "", "PUSCH PDU Parameters ");
    proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_Pusch_Pdu);

	proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_pdu_pduBitmap, tvb, offset, 0);  
    proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_pdu_RNTI, tvb, offset, 0);
	proto_tree_add_uint32(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_pdu_Handle, tvb, offset, 0);

	  return 0;
}

static int dissect_BWP(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{
    proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_Bwp, tvb, *offset,6, "", "BWP Parameters ");
    proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_Bwp);

	 proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_BWPSize, tvb, offset, 0);  
	 proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_BWPStart, tvb, offset, 0);  
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_SubcarrierSpacing, tvb, offset, 0); 
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_CyclicPrefix, tvb, offset, 0); 

	  return 0;
}
static int dissect_PUSCH_Info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{
     proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_PUSCH_Info, tvb, *offset,9, "", "PUSCH Info Parameters ");
     proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_PUSCH_Info);

	 proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_info_targetCodeRate, tvb, offset, 0);  
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_info_qamModOrder, tvb, offset, 0); 

	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_info_mcsIndex, tvb, offset, 0); 
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_info_mcsTable, tvb, offset, 0); 
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_info_TransformPrecoding, tvb, offset, 0); 
	
	 proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_info_dataScramblingId, tvb, offset, 0);  
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_info_nrOfLayers, tvb, offset, 0); 

	  return 0;
}
static int dissect_PRACH_PDU_DMRS(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{
    proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_PRACH_PDU_DMRS, tvb, *offset,9, "", "PRACH_PDU_DMRS Parameters ");
    proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_PRACH_PDU_DMRS);

	 proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_dmrs_ulDmrsSymbPos, tvb, offset, 0);  
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_dmrs_dmrsConfigType, tvb, offset, 0); 
	 proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_dmrs_ulDmrsScramblingId, tvb, offset, 0);  
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_dmrs_SCID, tvb, offset, 0); 

	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_dmrs_numDmrsCdmGrpsNoData, tvb, offset, 0); 
	 proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_dmrs_dmrsPorts, tvb, offset, 0);  

	  return 0;
}
static int dissect_PUSCH_Alloc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{ 
    
    proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_PUSCH_Alloc, tvb, *offset,11, "", "PUSCH_Alloc Parameters ");
    proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_PUSCH_Alloc);

	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_alloc_resourceAlloc, tvb, offset, 0); 
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_alloc_rbBitmap, tvb, offset, 0); 

	proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_alloc_rbStart, tvb, offset, 0);
	proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_alloc_rbSize, tvb, offset, 0);

	
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_alloc_VRBtoPRBMapping, tvb, offset, 0); 
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_alloc_FrequencyHopping, tvb, offset, 0); 

	proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_alloc_txDirectCurrentLocation, tvb, offset, 0);
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_pusch_alloc_uplinkFrequencyShift7p5khz, tvb, offset, 0); 

	  return 0;
}
static int dissect_Res_Alloc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{
    
    proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_Res_Alloc, tvb, *offset,2, "", "Resource Allocation Parameters ");
     proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_Res_Alloc);
  
   // Resource Allocation in time domain:
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_resalloc_StartSymbolIndex, tvb, offset, 0); 
	 proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_req_resalloc_NrOfSymbols, tvb, offset, 0); 

	   return 0;
}

//PUCCH_PDU
static int dissect_PUCCH_PDU_Struct(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{
 proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_PUCCH_PDU_Struct, tvb, *offset,6, "", "PUCCH PDU Parameters ");
 proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_PUCCH_PDU_Struct);

    proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_RNTI, tvb, offset, 0);
	 proto_tree_add_uint32(ul_tti_Msg_body_header_tree, hf_nfapi_Handle, tvb, offset, 0);

    return 0;
}
static int dissect_Pucch_Allocation_Fd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{
	
 proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_Pucch_Allocation_Fd, tvb, *offset,4, "", "Pucch Allocation Fd Parameters ");
 proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_Pucch_Allocation_Fd);

  proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_prbStart, tvb, offset, 0);
  proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_prbSize, tvb, offset, 0);  
   return 0;
}

static int dissect_Pucch_Allocation_td(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{
	
 proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_Pucch_Allocation_td, tvb, *offset,2, "", "Pucch Allocation td Parameters ");
 proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_Pucch_Allocation_td);

   proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_StartSymbolIndex, tvb, offset, 0);
   proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_NrOfSymbols, tvb, offset, 0);  
   return 0;
}
static int dissect_Hopping_Information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{
	
 proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_Hopping_Information, tvb, *offset,9, "", "Hopping Information Parameters ");
 proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_Hopping_Information);

   proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_freqHopFlag, tvb, offset, 0); 
   proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_secondHopPRB, tvb, offset, 0); 
   proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_groupHopFlag, tvb, offset, 0); 
   proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_sequenceHopFlag, tvb, offset, 0); 
   proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_hoppingId, tvb, offset, 0); 
   proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_InitialCyclicShift, tvb, offset, 0); 

   return 0;
}
static int dissect_PUCCH_PDU_DMRS(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 pduType, guint16 msgLen, void* data _U_, guint* offset)
{
 proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_PUCCH_PDU_DMRS, tvb, *offset,4, "", "PUCCH PDU DMRS Parameters ");
 proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_PUCCH_PDU_DMRS);

   proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_AddDmrsFlag, tvb, offset, 0); 
   proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_DmrsScramblingId, tvb, offset, 0); 
   proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_DMRScyclicshift, tvb, offset, 0); 

   return 0;

}

static int dissect_Number_of_PDUs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 msgLen, void* data _U_, guint* offset, guint16 pduType)
{
		switch(pduType)
		{
			/* PRACH_PDU */
			case 0:
			{
				dissect_PRACH_PDU(tvb, pinfo, tree, msgLen, data, offset, pduType);
				msgLen -= 8;
			    dissect_Beamforming(tvb, pinfo, tree, msgLen, data, offset, pduType);

				break;
			}
			/* PUSCH_PDU */
			case 1:
			{
                dissect_PUSCH_PDU(tvb, pinfo, tree, msgLen, data, offset, pduType);
				msgLen -= 8;
				dissect_BWP(tvb, pinfo, tree, pduType, msgLen, data, offset);
				msgLen -= 6;
				dissect_PUSCH_Info(tvb, pinfo, tree, pduType, msgLen, data, offset);
				msgLen -= 9;
				dissect_PRACH_PDU_DMRS(tvb, pinfo, tree, pduType, msgLen, data, offset);
				msgLen -= 9;
				dissect_PUSCH_Alloc(tvb, pinfo, tree, pduType, msgLen, data, offset);
				msgLen -= 11;
				dissect_Res_Alloc(tvb, pinfo, tree, pduType, msgLen, data, offset);
				msgLen -= 2;
			    dissect_Beamforming(tvb, pinfo, tree, msgLen, data, offset, pduType);
				break;
			}
			/* PUCCH_PDU */
			case 2:
			{
				dissect_PUCCH_PDU_Struct(tvb, pinfo, tree, pduType, msgLen, data, offset);
				msgLen -= 6;

				dissect_BWP(tvb, pinfo, tree, pduType, msgLen, data, offset);
				

				proto_tree_add_uint8(tree, hf_nfapi_FormatType, tvb, offset, 0);
    			proto_tree_add_uint8(tree, hf_nfapi_multiSlotTxIndicator, tvb, offset, 0);
    			proto_tree_add_uint8(tree, hf_nfapi_pi2Bpsk, tvb, offset, 0);  

				 msgLen -= 9;

				//Pucch Allocation in frequency domain
    			dissect_Pucch_Allocation_Fd(tvb, pinfo, tree, pduType, msgLen, data, offset);
				msgLen -= 4;

    			//Pucch Allocation in time domain
    			dissect_Pucch_Allocation_td(tvb, pinfo, tree, pduType, msgLen, data, offset);
				msgLen -= 2;

    		    //dissect_Hopping_Information
    			dissect_Hopping_Information(tvb, pinfo, tree, pduType, msgLen, data, offset);

				proto_tree_add_uint16(tree, hf_nfapi_dataScramblingId, tvb, offset, 0); 
				proto_tree_add_uint8(tree, hf_nfapi_TimeDomainOccIdx, tvb, offset, 0); 
				proto_tree_add_uint8(tree, hf_nfapi_PreDftOccIdx, tvb, offset, 0); 
				proto_tree_add_uint8(tree, hf_nfapi_PreDftOccLen, tvb, offset, 0);  

				msgLen -= 14;
				//dissect_PUCCH_PDU_DMRS
				dissect_PUCCH_PDU_DMRS(tvb, pinfo, tree, pduType, msgLen, data, offset);

				proto_tree_add_uint8(tree, hf_nfapi_SRFlag, tvb, offset, 0); 
				proto_tree_add_uint8(tree, hf_nfapi_BitLenHarq, tvb, offset, 0); 
				proto_tree_add_uint16(tree, hf_nfapi_BitLenCsiPart1, tvb, offset, 0); 
				proto_tree_add_uint16(tree, hf_nfapi_BitLenCsiPart2, tvb, offset, 0);  

				msgLen -= 10;
				//Beamforming call
				dissect_Beamforming(tvb, pinfo, tree, msgLen, data, offset, pduType);


				break;
			}
			/* SRS_PDU */
			case 3:
			{
				 proto_item *uL_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_Srs_pdu, tvb, *offset,msgLen, "", "SRS PDU Parameters ");
    			 proto_tree *uL_tti_Msg_body_tree = proto_item_add_subtree(uL_tti_Msg_body_ti, ett_5gfapi_UL_tti_Srs_pdu);

					proto_tree_add_uint16(uL_tti_Msg_body_tree, hf_5gfapi_RNTI ,tvb, offset, 0);  
					proto_tree_add_uint32(uL_tti_Msg_body_tree, hf_5gfapi_Handle , tvb, offset, 0);

					msgLen -= 6;
					//call BWP
					dissect_BWP(tvb, pinfo, tree, pduType, msgLen, data, offset);  // 6 bytes
					
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_numAntPorts, tvb, offset, 0); 
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_numSymbols, tvb, offset, 0); 
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_numRepetitions, tvb, offset, 0); 

					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_timeStartPosition, tvb, offset, 0); 
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_configIndex, tvb, offset, 0); 
					proto_tree_add_uint16(uL_tti_Msg_body_tree, hf_5gfapi_sequenceId,tvb, offset, 0);  

					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_bandwidthIndex, tvb, offset, 0); 
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_combSize, tvb, offset, 0); 
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_combOffset, tvb, offset, 0); 
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_cyclicShift, tvb, offset, 0); 

					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_frequencyPosition, tvb, offset, 0); 
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_frequencyShift, tvb, offset, 0); 
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_frequencyHopping, tvb, offset, 0); 

					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_groupOrSequenceHopping, tvb, offset, 0); 
					proto_tree_add_uint8(uL_tti_Msg_body_tree, hf_5gfapi_resourceType, tvb, offset, 0); 
					proto_tree_add_uint16(uL_tti_Msg_body_tree, hf_5gfapi_Tsrs,tvb, offset, 0);  
					proto_tree_add_uint16(uL_tti_Msg_body_tree, hf_5gfapi_Toffset,tvb, offset, 0);  


					msgLen -= 26;
					// call Beamforming structure
					dissect_Beamforming(tvb, pinfo, tree, msgLen, data, offset, pduType);
					break;
			}
			default:
			{
				break;
			}

		};
	
	return 0;

} 

static int dissect_UL_tti_Msg_body(tvbuff_t *tvb, packet_info *pinfo , proto_tree *tree, guint32 msgLen, void* data , guint* offset)
{
    guint8 nPDUs = 0;
    guint8 num_group = 0;
    guint8 num_ue = 0;
    guint16 PDU_Types = 0;

    proto_item *ul_tti_Msg_body_ti = proto_tree_add_string_format(tree, hf_5gfapi_UL_tti_Msg_body, tvb, *offset,msgLen, "", "UL_TTI.request Body");
    proto_tree *ul_tti_Msg_body_header_tree = proto_item_add_subtree(ul_tti_Msg_body_ti, ett_5gfapi_UL_tti_Msg_body);

	proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_request_sfn, tvb, offset, 0);  
    proto_tree_add_uint16(ul_tti_Msg_body_header_tree, hf_nfapi_ul_tti_request_slot, tvb, offset, 0);  

	nPDUs = proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_number_pdus, tvb, offset, 0); 
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_rachpresent, tvb, offset, 0); 
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_nULSCH, tvb, offset, 0); 
	proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_nULCCH, tvb, offset, 0); 
	num_group =  proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_nGroup, tvb, offset, 0); 
	
	
  for(int i = 0; i < nPDUs; i++)
   {
        guint16 pduSize = tvb_get_guint16(tvb, *offset+2, ENC_LITTLE_ENDIAN);

        proto_item *Number_of_PDUs_ti = proto_tree_add_string_format(tree, hf_5gfapi_Number_of_PDUs, tvb, *offset, pduSize, "", "Number of PDUs");
	    proto_tree *Number_of_PDUs_tree = proto_item_add_subtree(Number_of_PDUs_ti, ett_5gfapi_Number_of_PDUs);

	    PDU_Types = proto_tree_add_uint16(Number_of_PDUs_tree, hf_nfapi_ul_tti_request_pdu_type, tvb, offset, 0);  
		proto_tree_add_uint16(Number_of_PDUs_tree, hf_nfapi_pdu_size, tvb, offset, 0);   

        
		 dissect_Number_of_PDUs(tvb, pinfo, Number_of_PDUs_tree,  pduSize-4, data, offset, PDU_Types);

    }

    if(num_group > 0)
	{
		 num_ue = proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_nUe, tvb, offset, 0); 	 

		for(guint8 i = 0; i < num_ue; i++)
       	{
			proto_tree_add_uint8(ul_tti_Msg_body_header_tree, hf_nfapi_pduidx, tvb, offset, 0);            
		 }
	}
 
   return 0;
}
/*** UL_TTI.Request Dissection Functions ends***/

static int dissect_5gfapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "5GFAPI");

	guint16 msg_id = tvb_get_guint16(tvb, 2, ENC_LITTLE_ENDIAN);

    guint32 msg_len = tvb_get_guint32(tvb, 4, ENC_LITTLE_ENDIAN);


	const gchar* message_str = val_to_str_const(msg_id, message_id_vals, "Unknown");

	col_clear(pinfo->cinfo,COL_INFO);
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", message_str);

	proto_item *msg_tree_ti = proto_tree_add_string_format(tree, hf_5gfapi_message_tree, tvb, 0, msg_len, "", message_str);

	proto_tree *msg_tree = proto_item_add_subtree(msg_tree_ti, ett_5gfapi_message_tree);

	guint offset = 0;
        
	/* Dissecting the 8 bytes of FAPI header */
	dissect_p7p5_header(tvb, pinfo, msg_tree, data, &offset);
	
	switch (msg_id)
	{			
		/* PARAM.request */
		case 0x00:
		{
			break;
		}
		/* PARAM.response */
		case 0x01:
		{
			/* Dissect your message body here */
			break;
		}
		/* CONFIG.request */
		case 0x02:
		{
			break;
		}
		/* CONFIG.response */
		case 0x03:
		{
			break;
		}
		/* START.request */
		case 0x04:
		{
			break;
		}
		/* STOP.request */
		case 0x05:
		{
			break;
		}
		/* STOP.indication */
		case 0x06:
		{
			break;
		}
		/* ERROR.indication */
		case 0x07:
		{
			break;
		}
		/* DL_TTI.request */
		case 0x80:
		{
			dissectDlTtiReq(tvb, pinfo, msg_tree, msg_len, data, &offset);
			break;
		}
		/* UL_TTI.request */
		case 0x81:
		{
			dissect_UL_tti_Msg_body(tvb, pinfo, msg_tree, msg_len, data, &offset);
			break;
		}
		/* SLOT.indication */
		case 0x82:
		{
			break;
		}
		/* UL_DCI.request */
		case 0x83:
		{
			dissect_ul_dci_request(tvb, pinfo, tree, data, &offset, msg_len);
            break;
		}
		/* TX_Data.request */
		case 0x84:
		{
			break;
		}
		/* Rx_Data.indication */
		case 0x85:
		{
			break;
		}
		/* CRC.indication */
		case 0x86:
		{
			break;
		}
		/* UCI.indication */
		case 0x87:
		{
			break;
		}
		/* SRS.indication */
		case 0x88:
		{
			break;
		}
		/* RACH.indication */
		case 0x89:
		{
			break;
		}

		default:
		{
			/* todo : is this vendor extention? */
			break;
		}
	};

	return tvb_captured_length(tvb);
}


void proto_register_5gfapi(void)
{

	static hf_register_info hf[] =
	{
		{ &hf_5gfapi_message_tree, { "Message tree", "5gfapi.message_tree", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_p7_p5_message_header, { "P7 P5 Header", "5gfapi.p7_p5_message_header",	FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_p7_p5_message_header_num_of_msgs, { "Num of Msgs Included in PHY API MSG", "5gfapi.p7_p5_message_header.num_of_msgs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_p7_p5_message_header_phy_id, { "PHY ID", "5gfapi.p7_p5_message_header.phy_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_p7_p5_message_header_message_id, { "Message Type ID", "5gfapi.p7_p5_message_header.message_id", FT_UINT16, BASE_HEX_DEC, VALS(message_id_vals), 0x0, NULL, HFILL } },
		{ &hf_5gfapi_p7_p5_message_header_message_length, { "Message Length", "5gfapi.p7_p5_message_header.message_length", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_error_code, { "Error Code", "5gfapi.error.code", FT_UINT8, BASE_DEC, VALS(nrfapi_error_vals), 0x0, NULL, HFILL } },

		/*UL DCI*/
		{ &hf_5gfapi_ul_dci_message_body, { "UL DCI Message Body", "5gfapi.uldci_message_body", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_sfn, { "SFN", "5gfapi.uldci.sfn", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_slot, { "SLOT", "5gfapi.uldci.slot", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_num_pdcch_pdu, { "Num of PDCCH Pdus", "5gfapi.uldci.numPdus", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_pdu_list, { "PDU List", "5gfapi.uldci.pdulist", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },  
        { &hf_5gfapi_pdu_idx, { "PDU idx", "5gfapi.uldci.pdulist.idx", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_pdu_type, { "PDU Type", "5gfapi.uldci.pduType", FT_UINT16, BASE_DEC, VALS(dl_tti_pdu_type_vals), 0x0, NULL, HFILL } },
		{ &hf_5gfapi_pdu_size, { "PDU Size", "5gfapi.uldci.pduSize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_pdcch_pdu_config, { "PDCCH PDU Config", "5gfapi.uldci.pdulist.idx.pdcchPdu", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_ul_dci_pdcch_pdu_bwp, { "ul_dci_pdcch_pdu_bwp", "5gfapi.uldci.pdulist.idx.pdcchPdu.bwp", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_bwp_size, { "Size", "5gfapi.uldci.pdulist.idx.pdcchPdu.bwp.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_bwp_start, { "Start", "5gfapi.uldci.pdulist.idx.pdcchPdu.bwp.start", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_subcarrier_spacing, { "Subcarrier Spacing", "5gfapi.uldci.pdulist.idx.pdcchPdu.bwp.scs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_cyclic_prefix, { "CyclicPrefix", "5gfapi.uldci.pdulist.idx.pdcchPdu.bwp.cp", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_ul_dci_pdcch_pdu_coreset, { "ul_dci_pdcch_pdu_coreset", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_StartSymbolIndex, { "Start Sym Index", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.startSymIdx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_DurationSymbols, { "Sym Duration", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.symDuration", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_FreqDomainResource, { "FreqDomRes", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.freqDomResrc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_CceRegMappingType, { "CceRegMappingType", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.CceRegMapType", FT_UINT8, BASE_DEC, VALS(nrfapi_cceRegMapping_types_vals), 0x0, NULL, HFILL } },
		{ &hf_5gfapi_RegBundleSize, { "REG BundleSz", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.regBundleSz", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_InterleaverSize, { "InetrleaverSz", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.interleaverSz", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_CoreSetType, { "CoresetType", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_ShiftIndex, { "ShiftIdx", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.shiftIdx", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_precoderGranularity, { "PrecoderGranularity", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.precoder_gran", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_numDlDci, { "Coreset Num DL DCIs", "5gfapi.uldci.pdulist.idx.pdcchPdu.coreset.numDlDci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_dl_dci_structure, { "DL DCI_structure", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_rnti, { "RNTI", "5gfapi.uldci.pdulist.idx.pdcchPdu.dci.rnti", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_scramblingId, { "Scrambling Id", "5gfapi.uldci.pdulist.idx.pdcchPdu.dci.scramblingId", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_ScramblingRNTI, { "Scrambling RNTI", "5gfapi.uldci.pdulist.idx.pdcchPdu.dci.scramblingRnti", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_CceIndex, { "CCE Index", "5gfapi.uldci.pdulist.idx.pdcchPdu.dci.cceIdx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_AggregationLevel, { "AggrLvl", "5gfapi.uldci.pdulist.idx.pdcchPdu.dci.AL", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_dl_dci_beamforming_info, { "Precoding BeamformingInfo", "5gfapi", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_numPRGs, { "Num of PRGs", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.bmf.numPrg", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_prgSize, { "PRG Size", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.bmf.PrgSz", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_digBFInterfaces, { "Dig BF", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.bmf.digBFInterfaces", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_PMidx, { "PM Index", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.bmf.PMidx", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_beamIdx, { "Beam Index", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.bmf.beamIdx", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_dl_dci_tx_pwr_info, { "Tx Power Info", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.txPwrInfo", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_beta_pdcch_1_0, { "beta pdcch_1_0", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.txPwrInfo.beta1_0", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_powerControlOffsetSS, { "Power Control OffsetSS", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.txPwrInfo.powerControlOffsetSS", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_PayloadSizeBits, { "DCI PayloadSz Bits", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.payloadSz", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_5gfapi_Payload, { "DCI Payload", "5gfapi.uldci.pdulist.idx.pdcchPdu.dlDciPdu.txPwrInfo.payload", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		/**DL-TTI Request**/
        { &hf_5gfapi_dl_tti_request, { "DL_TTI.request", "5gfapi.dl_tti_request", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_num_pdus, { "No of PDUs", "5gfapi.dl_tti_request.num_pdus", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_num_group, { "No of Groups", "5gfapi.dl_tti_request.num_group", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_dl_tti_request_pdu_info, { "PDU info", "5gfapi.dl_tti_request.pdu_info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_5gfapi_dl_tti_request_pdcch_pdu_bwp_info, { "BWP info", "5gfapi.dl_tti_request.pdu_type.pdu_info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	    { &hf_5gfapi_pdcch_pdu_bwp_size, { "SIZE", "5gfapi.dl_tti_request.pdcch_pdu_info.bwp.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
		{ &hf_5gfapi_pdcch_pdu_bwp_start, { "START", "5gfapi.dl_tti_request.pdcch_pdu_info.bwp.start", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
		{ &hf_5gfapi_pdcch_pdu_bwp_subcarrier_spacing, { "Subcarrier Spacing", "5gfapi.dl_tti_request.pdcch_pdu_info.bwp.subcarrier_spacing", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
		{ &hf_5gfapi_pdcch_pdu_bwp_cyclic_prefix, { "Cyclic Prefix", "5gfapi.dl_tti_request.pdcch_pdu_info.bwp.cyclic_prefix", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

			/*PDSCH PDU*/
			{ &hf_5gfapi_dl_tti_pdsch_pdu, { "PDSCH PDU", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_pduBitmap, { "PDU Bitmap", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.pduBitmap", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_rnti, { "RNTI", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.rnti", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_pdu_index, { "PDU Index", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.pduIndex", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			
			{ &hf_5gfapi_dl_tti_pdsch_pdu_bwp, { "BWP", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.bwp", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_bwp_size, { "BWP Size", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.bwp.bwp_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_bwp_start, { "BWP Start", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.bwp.bwp_start", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_sub_carrier_spacing, { "Sub carrier spacing", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.bwp.scs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_cyclic_prefix, { "Cyclic prefix", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.bwp.cyclic_prefix", FT_UINT8, BASE_DEC, VALS(dl_tti_cyclicPrefix_vals), 0x0, NULL, HFILL } },
		
			{ &hf_5gfapi_dl_tti_pdsch_pdu_Codeword_info, { "Codeword Info", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_nrOfCodewords, { "No Of Codewords", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo.nrOfCodewords", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_pdsch_pdu_Codeword, { "Codeword", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo.cw", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_targetCodeRate, { "Target Code Rate", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo.cw.targetCodeRate", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_qamModOrder, { "qam Modulation Order", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo.cw.qamModOrder", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_mcsIndex, { "MCS Index", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo.cw.mcsIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } }, 
			{ &hf_5gfapi_dl_tti_request_mcsTable, { "MCS Table", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo.cw.mcsTable", FT_UINT8, BASE_DEC, VALS(dl_tti_mcsTable_vals), 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_rvIndex, { "RV Index", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo.cw.rvIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_tbSize, { "TB Size", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo.cw.tbSize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
		
			{ &hf_5gfapi_dl_tti_request_dataScramblingId, { "Data Scrambling Id", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.dataScramblingId", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } }, 
			{ &hf_5gfapi_dl_tti_request_nrOfLayers, { "No of layers", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.nrOfLayers", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_transmissionScheme, { "Transmission Scheme", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.transmissionScheme", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } }, 
			{ &hf_5gfapi_dl_tti_request_refPoint, { "Ref Point", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.refPoint", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
		//	{ &hf_5gfapi_dl_tti_request_tbSize, { "TB Size", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cwInfo.cw.tbSize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			
			{ &hf_5gfapi_dl_tti_pdsch_pdu_dmrs, { "DMRS", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.dmrs", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_dlDmrsSymbPos, { "DL DMRS Symbol Position", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.dmrs.dlDmrsSymbPos", FT_UINT16, BASE_DEC, VALS(dl_tti_dlDmrsSymbPos_vals), 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_dmrsConfigType, { "DMRS Config Type", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.dmrs.dmrsConfigType", FT_UINT8, BASE_DEC, VALS(dl_tti_dmrsConfigType_vals), 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_dlDmrsScramblingId, { "DL DMRS Scrambling Id", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.dmrs.dlDmrsScramblingId", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } }, 
			{ &hf_5gfapi_dl_tti_request_SCID, { "SCID", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.dmrs.scid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_numDmrsCdmGrpsNoData, { "Number of DMRS Cdm Grps No Data", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.dmrs.numDmrsCdmGrpsNoData", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_dmrsPorts, { "DMRS Ports", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.dmrs.dmrsPorts", FT_UINT16, BASE_DEC, VALS(dl_tti_dmrsPorts_vals), 0x0, NULL, HFILL } },	
			//{ &hf_5gfapi_dl_tti_request_cyclic_prefix, { "Cyclic prefix", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.bwp.cyclic_prefix", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
		
			{ &hf_5gfapi_dl_tti_pdsch_pdu_allocFreqDomain, { "Pdsch Allocation in frequency domain", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.allocFreqDomain", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_resourceAlloc, { "Resource Alloc", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.allocFreqDomain.resourceAlloc", FT_UINT8, BASE_DEC, VALS(dl_tti_resourceAlloc_vals), 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_rbBitmap, { "RB Bitmap", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.allocFreqDomain.rbBitmap", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_rbStart, { "RB Start", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.allocFreqDomain.rbStart", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } }, 
			{ &hf_5gfapi_dl_tti_request_rbSize, { "RB Size", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.allocFreqDomain.rbSize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_VRBtoPRBMapping, { "VRB to PRB Mapping", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.allocFreqDomain.VRBtoPRBMapping", FT_UINT8, BASE_DEC, VALS(dl_tti_VRBtoPRBMapping_vals), 0x0, NULL, HFILL } },
		
			{ &hf_5gfapi_dl_tti_pdsch_pdu_allocTimeDomain, { "Pdsch Allocation in time domain", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.allocTimeDomain", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_StartSymbolIndex, { "Start Symbol Index", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.allocTimeDomain.StartSymbolIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_NrOfSymbols, { "No Of Symbols", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.allocTimeDomain.NrOfSymbols", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } }, 
		
			{ &hf_5gfapi_dl_tti_pdsch_pdu_ptrs, { "PTRS", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.ptrs", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_PTRSPortIndex, { "PTRS Port Index", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.ptrs.PTRSPortIndex", FT_UINT8, BASE_DEC, VALS(dl_tti_PTRSPortIndex_vals), 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_PTRSTimeDensity, { "PTRS Time Density", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.ptrs.PTRSTimeDensity", FT_UINT8, BASE_DEC, VALS(dl_tti_PTRSTimeDensity_vals), 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_PTRSFreqDensity, { "PTRS Freq Density", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.ptrs.PTRSFreqDensity", FT_UINT8, BASE_DEC, VALS(dl_tti_PTRSFreqDensity_vals), 0x0, NULL, HFILL } },	
			{ &hf_5gfapi_dl_tti_request_PTRSReOffset, { "PTRS Re Offset", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.ptrs.PTRSReOffset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } }, 
			{ &hf_5gfapi_dl_tti_request_nEpreRatioOfPDSCHToPTRS, { "nEpre Ratio Of PDSCH To PTRS", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.ptrs.nEpreRatioOfPDSCHToPTRS", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } }, 
		
			{ &hf_5gfapi_dl_tti_pdsch_pdu_txPower, { "Tx Power Info", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.txPower", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_powerControlOffset, { "Power Control Offset", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.txPower.powerControlOffset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_requst_powerControlOffsetSS, { "Power Control Offset SS", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.txPower.powerControlOffsetSS", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		
			{ &hf_5gfapi_dl_tti_pdsch_pdu_cbgFields, { "CBG Fields", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cbgFields", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_request_IsLastCbPresent, { "Is Last Cb Present", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cbgFields.IsLastCbPresent", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_requst_isInlineTbCrc, { "Is Inline Tb Crc", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cbgFields.isInlineTbCrc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
			{ &hf_5gfapi_dl_tti_requst_dlTbCrc, { "DL Tb Crc", "5gfapi.dl_tti_request.pdu_info.pdsch_pdu.cbgFields.dlTbCrc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },


		/** CSI RS PDU **/
		{ &hf_5gfapi_csi_rs_bwp_pdu, { "CSI RS CORESET INFO", "5gfapi.dl_tti_request.csi_rs", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_bwp_pdu_size, { "BWP Size", "5gfapi.dl_tti_request.csi_rs.bwp_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_bwp_pdu_start, { "BWP Start", "5gfapi.dl_tti_request.csi_rs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_bwp_pdu_subcarrier_spacing, { "Subcarrier Spacing", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_bwp_pdu_cyclic_prefix, { "Cyclic Prefix", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_5gfapi_csi_rs_pdu, { "CSI RS INFO", "5gfapi.dl_tti_request.csi_rs", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_start_rb, { "Start RB", "5gfapi.dl_tti_request.csi_rs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_nr_of_rbs, { "Nr Of RBs", "5gfapi.dl_tti_request.csi_rs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_csi_type, { "CSI Type", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, VALS(dl_tti_csi_rs_type), 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_row, { "Row", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_freq_domain, { "Freq Domain", "5gfapi.dl_tti_request.csi_rs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_symbL0, { "SymbL0", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_symbl1, { "SymbL1", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_cdm_type, { "CDM Type", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, VALS(dl_tti_csi_rs_cmd_type), 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_freq_density, { "Freq Density", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_scramb_id, { "Scramb Id", "5gfapi.dl_tti_request.csi_rs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_5gfapi_csi_rs_pdu_tx_power_info, { "CSI RS TX POWER INFO", "5gfapi.dl_tti_request.csi_rs", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_tx_power_info_power_control_offset, { "Power Control Offset", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_5gfapi_csi_rs_pdu_tx_power_info_power_control_offsetSS, { "Power Control Offset SS", "5gfapi.dl_tti_request.csi_rs", FT_UINT8, BASE_DEC, VALS(dl_tti_csi_rs_tx_power_control_offset_ss), 0x0, NULL, HFILL } },

	/** SSB PDU **/
	{ &hf_5gfapi_pdcch_pdu_ssb, { "PDCCH SSB INFO", "5gfapi.dl_tti_request.pdcch_pdu_info.ssb", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_ssb_phy_cell_id, { "Cell Id", "5gfapi.dl_tti_request.pdcch_pdu_info.ssb.cell_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_ssb_beta_pss, { "Beta Pss", "5gfapi.dl_tti_request.pdcch_pdu_info.ssb", FT_UINT8, BASE_DEC, VALS(dl_tti_ssb_pdu_beta_pss), 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_ssb_block_index, { "Block Index", "5gfapi.dl_tti_request.pdcch_pdu_info.ssb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_ssb_subcarrier_offset, { "Subcarrier Offset", "5gfapi.dl_tti_request.pdcch_pdu_info.ssb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_ssb_offset_point_a, { "Offset Point A", "5gfapi.dl_tti_request.pdcch_pdu_info.ssb", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_ssb_bch_payload_flag, { "Payload Flag", "5gfapi.dl_tti_request.pdcch_pdu_info.ssb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_5gfapi_pdcch_pdu_mib, { "PDCCH PDU MIB INFO", "5gfapi.dl_tti_request.pdcch_pdu_mib_info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_mib_bch_payload, { "Bch Payload", "5gfapi", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_mib_dmrs_type_a_psition, { "Dmrs TypeA Position", "5gfapi.dl_tti_request.pdcch_pdu_mib_info.dmrs_typea_position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_mib_pdcch_config_sib1, { "Pdcch Config Sib1", "5gfapi.dl_tti_request.pdcch_pdu_mib_info.pdcch_config_sib1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_mib_cell_barred, { "Cell Barred", "5gfapi.dl_tti_request.pdcch_pdu_mib_info.cell_barred", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_pdcch_pdu_mib_intra_freq_reselection, { "Intra Freq Reselection", "5gfapi.dl_tti_request.pdcch_pdu_mib_info.intra_freq_reselection", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

	/**UL_TTI.Request**/	
	{ &hf_5gfapi_UL_tti_Msg_body,{ "UL TTI Request Message Body", "5gfapi.UL_tti_Msg_body",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_nfapi_ul_tti_request_sfn,{"UL TTI Request Slot fram number", "nfapi.ul.tti.request.sfn", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_request_slot,{"UL TTI Request Slot ", "nfapi.ul.tti.request.slot", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_nfapi_number_pdus,{ "UL TTI Request Number of PDU ", "nfapi.ul.tti.request.number.pdus", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_rachpresent,{ "UL TTI Request RachPresent", "nfapi.ul.tti.request.rachpresent", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_nULSCH,{ "UL TTI Request nULSCH", "nfapi.ul.tti.request.nULSCH", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_nULCCH,{ "UL TTI Request nULCCH", "nfapi.ul.tti.request.nULCCH", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_nGroup,{ "UL TTI Request nGroup", "nfapi.ul.tti.request.nGroup", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_5gfapi_Number_of_PDUs,{ "Number of PDU info", "5gfapi.ul_tti_request.pdu_info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_request_pdu_type,{ "UL TTI Request PDU Type", "nfapi.ul.tti.request.pdu.type", FT_UINT16, BASE_HEX_DEC, VALS(nfapi_ul_tti_request_pdu_type_vals), 0x0, NULL, HFILL } },
	{ &hf_nfapi_pdu_size,{ "UL TTI Request PDU Size", "nfapi.ul.tti.request.pdu.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_nfapi_nUe,{ "UL TTI Request nUe", "nfapi.ul.tti.request.nUe", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_pduidx,{ "UL TTI Request PDUIdx", "nfapi.ul.tti.request.pduidx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_5gfapi_UL_tti_Prach_pdu,{ "PRACH PDU Parameters", "5gfapi.UL_tti_Prach_pdu",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	
	
	//Prach pdu
	{ &hf_nfapi_ul_tti_req_prach_pdu_physCellID,{"Prach pdu physCellID ", "nfapi.ul.tti.request.prach.pdu.physCellID", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_prach_pdu_NumPrachOcas,{ "Prach pdu NumPrachOcas", "nfapi.ul.tti.request.prach.pdu.NumPrachOcas", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_prach_pdu_prachFormat,{ "Prach pdu prachFormat", "nfapi.ul.tti.request.prach.pdu.prachFormat", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_prach_pdu_numRa,{ "Prach pdu numRa", "nfapi.ul.tti.request.prach.pdu.numRa", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_prach_pdu_prachStartSymbol,{ "Prach pdu prachStartSymbol", "nfapi.ul.tti.request.prach.pdu.prachStartSymbol", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_prach_pdu_numCs,{"Prach pdu numCs ", "nfapi.ul.tti.request.prach.pdu.numCs", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	
	
	//Beamforming
	{ &hf_5gfapi_UL_tti_beamforming,{ "Beamforming Parameters", "5gfapi.UL_tti_beamforming",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_nfapi_ul_tti_req_beamforming_numPRGs,{"Beamforming numPRGs ", "nfapi.ul.tti.request.beamforming.numPRGs", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_beamforming_prgSize,{"Beamforming prgSize ", "nfapi.ul.tti.request.req.beamforming.prgSize", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_beamforming_digBFInterface,{ "Beamforming digBFInterface", "nfapi.ul.tti.request.beamforming.digBFInterface", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_nfapi_ul_tti_req_beamforming_beamIdx,{"Beamforming beamIdx ", "nfapi.ul.tti.request.beamforming.beamIdx", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	
	
	 //PUSCH PDU
	{ &hf_5gfapi_UL_tti_Pusch_Pdu,{ "Pusch Pdu Parameters", "5gfapi.UL_tti_Pusch_Pdu",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_nfapi_ul_tti_req_pusch_pdu_pduBitmap,{"UL TTI Request Pusch pdu pduBitmap ", "nfapi.ul.tti.request.pusch.pdu.pduBitmap", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_pdu_RNTI,{"UL TTI Request pusch pdu RNTI ", "nfapi.ul.tti.request.req.pusch.pdu.RNTI", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_pdu_Handle,{ "UL TTI Request pusch pdu Handle", "nfapi.ul.tti.request.pusch.pdu.Handle", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	
	//BWP
	 { &hf_5gfapi_UL_tti_Bwp, { "BWP Parameters", "5gfapi.UL_tti_bwp",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_nfapi_ul_tti_req_BWPSize,{" BWPSize ", "nfapi.ul.tti.request.req.BWPSize", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_BWPStart,{" BWPStart ", "nfapi.ul.tti.request.BWPStart", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } }, 
	{ &hf_nfapi_ul_tti_req_SubcarrierSpacing,{ "SubcarrierSpacing", "nfapi.ul.tti.request.SubcarrierSpacing", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_CyclicPrefix,{ " CyclicPrefix", "nfapi.ul.tti.request.CyclicPrefix", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } }, 	
	
	//PUSCH information always included
	 { &hf_5gfapi_UL_tti_PUSCH_Info,{ "PUSCH information Parameters", "5gfapi.UL_tti_PUSCH_Info",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_nfapi_ul_tti_req_pusch_info_targetCodeRate,{"Pusch info targetCodeRate ", "nfapi.ul.tti.request.pusch.info.targetCodeRate", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_info_qamModOrder,{ " Pusch info qamModOrder", "nfapi.ul.tti.request.pusch.info.qamModOrder", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_info_mcsIndex,{ " Pusch info mcsIndex", "nfapi.ul.tti.request.pusch.info.mcsIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_info_mcsTable,{ " Pusch info mcsTable", "nfapi.ul.tti.request.pusch.info.mcsTable", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_info_TransformPrecoding, { " Pusch info TransformPrecoding", "nfapi.ul.tti.request.pusch.info.TransformPrecoding", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_info_dataScramblingId,{" Pusch info dataScramblingId ", "nfapi.ul.tti.request.pusch.info.dataScramblingId", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_info_nrOfLayers,{ " Pusch info nrOfLayers", "nfapi.ul.tti.request.pusch.info.nrOfLayers", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	
	//DMRS:
	{ &hf_5gfapi_UL_tti_PRACH_PDU_DMRS, { "PRACH PDU DMRS Parameters", "5gfapi.UL_tti_PRACH_PDU_DMRS",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	 
	{ &hf_nfapi_ul_tti_req_dmrs_ulDmrsSymbPos,{"Dmrs ulDmrsSymbPos ", "nfapi.ul.tti.request.req.dmrs.ulDmrsSymbPos", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_dmrs_dmrsConfigType,{ "Dmrs dmrsConfigType", "nfapi.ul.tti.request.beamforming.dmrs.dmrsConfigType", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_dmrs_ulDmrsScramblingId,{"Dmrs ulDmrsScramblingId ", "nfapi.ul.tti.request.dmrs.ulDmrsScramblingId", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_dmrs_SCID,{ "Dmrs SCID", "nfapi.ul.tti.request.dmrs_SCID", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_dmrs_numDmrsCdmGrpsNoData,{ "Dmrs numDmrsCdmGrpsNoData", "nfapi.ul.tti.request.dmrs_numDmrsCdmGrpsNoData", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_dmrs_dmrsPorts,{"Dmrs dmrsPorts ", "nfapi.ul.tti.request.dmrs_dmrsPorts", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	
	
	//Pusch Allocation in frequency domain:
	{ &hf_5gfapi_UL_tti_PUSCH_Alloc,{ "PUSCH Allocation Parameters", "5gfapi.UL_tti_PUSCH_Alloc",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	  
	{ &hf_nfapi_ul_tti_req_pusch_alloc_resourceAlloc,{ "Pusch alloc resourceAlloc", "nfapi.ul.tti.request.pusch.alloc.resourceAlloc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_alloc_rbBitmap,{ "Pusch alloc rbBitmap", "nfapi.ul.tti.request.pusch.alloc.rbBitmap", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_alloc_rbStart,{"Pusch alloc rbStart ", "nfapi.ul.tti.request.pusch.alloc.rbStart", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_alloc_rbSize,{"Pusch alloc rbSize ", "nfapi.ul.tti.request.pusch.alloc.rbSize", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_alloc_VRBtoPRBMapping,{ "Pusch alloc VRBtoPRBMapping", "nfapi.ul.tti.request.pusch.alloc.VRBtoPRBMapping", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_alloc_FrequencyHopping,{ "Pusch alloc FrequencyHopping", "nfapi.ul.tti.request.pusch.alloc.FrequencyHopping", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_alloc_txDirectCurrentLocation,{"Pusch alloc txDirectCurrentLocation ", "nfapi.ul.tti.request.pusch.alloc.txDirectCurrentLocation", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_pusch_alloc_uplinkFrequencyShift7p5khz,{ "Pusch alloc uplinkFrequencyShift7p5khz", "nfapi.ul.tti.request.pusch.alloc.uplinkFrequencyShift7p5khz", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	// Resource Allocation in time domain:
	{ &hf_5gfapi_UL_tti_Res_Alloc,{ "Resource Allocation Parameters", "5gfapi.UL_tti_Res_Alloc",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	 
	{ &hf_nfapi_ul_tti_req_resalloc_StartSymbolIndex,{ "Resource Allocation StartSymbolIndex", "nfapi.ul.tti.request.resalloc.StartSymbolIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_ul_tti_req_resalloc_NrOfSymbols, { "Resource Allocation NrOfSymbols", "nfapi.ul.tti.request.resalloc.NrOfSymbols", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

	//PUCCH_PDU
	
	{ &hf_5gfapi_UL_tti_PUCCH_PDU_Struct,{ "PUCCH PDU parameters", "5gfapi.UL_tti_PUCCH_PDU_Struct",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_nfapi_RNTI,{" RNTI ", "nfapi.ul.tti.request.RNTI", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_Handle, { "Handle", "nfapi.Handle", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	
	{ &hf_nfapi_FormatType, { "FormatType", "nfapi.ul.tti.request.FormatType", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_multiSlotTxIndicator, { "multiSlotTxIndicator", "nfapi.ul.tti.request.multiSlotTxIndicator", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_nfapi_pi2Bpsk, { "pi2Bpsk", "nfapi.ul.tti.request.pi2Bpsk", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	//Pucch Allocation in frequency domain
	{&hf_5gfapi_UL_tti_Pucch_Allocation_Fd,{ "Pucch Allocation Fd Parameters", "5gfapi.UL_tti_Pucch_Allocation_Fd",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_prbStart,{" prbStart", "nfapi.ul.tti.request.prbStart", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_prbSize,{" prbSize ", "nfapi.ul.tti.requestprbSize", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	
	//Pucch Allocation in time domain
	{&hf_5gfapi_UL_tti_Pucch_Allocation_td,{ "Pucch Allocation td Parameters", "5gfapi.UL_tti_Pucch_Allocation_td",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_StartSymbolIndex,{ "StartSymbolIndex", "nfapi.ul.tti.request.StartSymbolIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_NrOfSymbols,{ "NrOfSymbols", "nfapi.ul.tti.request.NrOfSymbols", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	//dissect_Hopping_Information
	{&hf_5gfapi_UL_tti_Hopping_Information,{ "Hopping_Information", "5gfapi.UL_tti_Hopping_Information",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_freqHopFlag,{ "freqHopFlag", "nfapi.ul.tti.request.freqHopFlag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_secondHopPRB,{" secondHopPRB ", "nfapi.ul.tti.secondHopPRB", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_groupHopFlag,{ "groupHopFlag", "nfapi.ul.tti.request.groupHopFlag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_sequenceHopFlag,  { "sequenceHopFlag", "nfapi.ul.tti.request.sequenceHopFlag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_hoppingId, {" hoppingId ", "nfapi.ul.tti.hoppingId", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_InitialCyclicShift,{" InitialCyclicShift ", "nfapi.ul.tti.InitialCyclicShift", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	
	
	{&hf_nfapi_dataScramblingId,{" dataScramblingId ", "nfapi.ul.tti.dataScramblingId", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_TimeDomainOccIdx,{ "TimeDomainOccIdx", "nfapi.ul.tti.request.TimeDomainOccIdx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_PreDftOccIdx,{ "PreDftOccIdx", "nfapi.ul.tti.request.PreDftOccIdx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_PreDftOccLen,{ "PreDftOccLen", "nfapi.ul.tti.request.PreDftOccLen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	//PUCCH_PDU_DMRS
	{&hf_5gfapi_UL_tti_PUCCH_PDU_DMRS,{ "PUCCH PDU DMRS Parameters", "5gfapi.UL_tti_PUCCH_PDU_DMRS",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_AddDmrsFlag,{ "AddDmrsFlag", "nfapi.ul.tti.request.AddDmrsFlag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_DmrsScramblingId,{" DmrsScramblingId ", "nfapi.ul.tti.DmrsScramblingId", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_DMRScyclicshift,{ " DMRScyclicshift", "nfapi.ul.tti.request.DMRScyclicshift", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	
	{&hf_nfapi_SRFlag,{ "SRFlag", "nfapi.ul.tti.request.SRFlag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_BitLenHarq,{ "BitLenHarq", "nfapi.ul.tti.request.BitLenHarq", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_BitLenCsiPart1,{" BitLenCsiPart1 ", "nfapi.ul.tti.BitLenCsiPart1", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{&hf_nfapi_BitLenCsiPart2,{" BitLenCsiPart2 ", "nfapi.ul.tti.BitLenCsiPart2", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },

	//SRS PDU
	{&hf_5gfapi_UL_tti_Srs_pdu,{ "SRS PDU Parameters", "5gfapi.UL_tti_SRS_PDU",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	
	//SRS PDU Parameters things
	{ &hf_5gfapi_RNTI,{" RNTI ", "nfapi.ul.tti.request.req.srs.pdu.RNTI", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_Handle,{" Handle", "nfapi.ul.tti.request.srs.pdu.Handle", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_5gfapi_numAntPorts,{ "numAntPorts", "nfapi.ul.tti.request.numAntPorts", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_numSymbols,{ "numSymbols", "nfapi.ul.tti.request.numSymbols", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_numRepetitions,{ "numRepetitions", "nfapi.ul.tti.request.numRepetitions", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_5gfapi_timeStartPosition,{ "timeStartPosition", "nfapi.ul.tti.request.timeStartPosition", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_configIndex,{ "configIndex", "nfapi.ul.tti.request.configIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_sequenceId,{"sequenceId", "nfapi.ul.tti.request.sequenceId", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_5gfapi_bandwidthIndex,{ "bandwidthIndex", "nfapi.ul.tti.request.bandwidthIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_combSize,{ "combSize", "nfapi.ul.tti.request.combSize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_combOffset,{ "combOffset", "nfapi.ul.tti.request.combOffset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_cyclicShift,{ "cyclicShift", "nfapi.ul.tti.request.cyclicShift", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_5gfapi_frequencyPosition,{ "frequencyPosition ", "nfapi.ul.tti.request.frequencyPosition", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_frequencyShift,{ "frequencyShift", "nfapi.ul.tti.request.frequencyShift", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_frequencyHopping,{ "frequencyHopping ", "nfapi.ul.tti.request.frequencyHopping", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	
	{ &hf_5gfapi_groupOrSequenceHopping,{ "groupOrSequenceHopping", "nfapi.ul.tti.request.configIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_resourceType,{ "resourceType", "nfapi.ul.tti.request.resourceType", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_Tsrs,{"Tsrs", "nfapi.ul.tti.request.Tsrs", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_5gfapi_Toffset,{ "Toffset", "nfapi.ul.tti.request.Toffset", FT_UINT16,BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
	
	};

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_5gfapi_message_tree,
		&ett_5gfapi_p7_p5_message_header,
		&ett_5gfapi_ul_dci_message_body,
		&ett_5gfapi_pdu_list,
		&ett_5gfapi_pdu_idx,
		&ett_5gfapi_pdcch_pdu_config,
		&ett_5gfapi_ul_dci_pdcch_pdu_bwp,
		&ett_5gfapi_ul_dci_pdcch_pdu_coreset,
		&ett_5gfapi_dl_dci_structure,
		&ett_5gfapi_dl_dci_beamforming_info,
		&ett_5gfapi_dl_dci_tx_pwr_info,
		&ett_5gfapi_dl_tti_request,
		&ett_5gfapi_dl_tti_request_pdu_info,
		&ett_5gfapi_dl_tti_pdsch_pdu,
		&ett_5gfapi_dl_tti_pdsch_pdu_bwp,
		&ett_5gfapi_dl_tti_pdsch_pdu_Codeword_info,
		&ett_5gfapi_dl_tti_pdsch_pdu_Codeword,
		&ett_5gfapi_dl_tti_pdsch_pdu_dmrs,
		&ett_5gfapi_dl_tti_pdsch_pdu_allocFreqDomain,
		&ett_5gfapi_dl_tti_pdsch_pdu_allocTimeDomain,
		&ett_5gfapi_dl_tti_pdsch_pdu_ptrs,
		&ett_5gfapi_dl_tti_pdsch_pdu_txPower,
		&ett_5gfapi_dl_tti_pdsch_pdu_cbgFields,
		&ett_5gfapi_UL_tti_Msg_body,
		&ett_5gfapi_Number_of_PDUs,
		&ett_5gfapi_UL_tti_Prach_pdu,
		&ett_5gfapi_UL_tti_beamforming,
		&ett_5gfapi_UL_tti_Pusch_Pdu,
		&ett_5gfapi_UL_tti_Bwp,
		&ett_5gfapi_UL_tti_PUSCH_Info,
		&ett_5gfapi_UL_tti_PRACH_PDU_DMRS,
		&ett_5gfapi_UL_tti_PUSCH_Alloc,
		&ett_5gfapi_UL_tti_Res_Alloc,
		&ett_5gfapi_UL_tti_PUCCH_PDU_Struct,
		&ett_5gfapi_UL_tti_Pucch_Allocation_Fd, 
		&ett_5gfapi_UL_tti_Pucch_Allocation_td,
		&ett_5gfapi_UL_tti_Hopping_Information,
		&ett_5gfapi_UL_tti_PUCCH_PDU_DMRS,
		&ett_5gfapi_UL_tti_Srs_pdu
    };

	/* Register protocol */
	proto_5gfapi = proto_register_protocol(
					"5gNR-FAPI-Protocol", 	/*Name*/
					"5G_FAPI", 				/*Short name*/
					"5gfapi"				/*filter name*/
					);

    proto_register_field_array(proto_5gfapi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
	
	register_dissector("5gfapi", dissect_5gfapi, proto_5gfapi);

}

// ----------------------------------------------------------------------------|

void proto_reg_handoff_5gfapi(void)
{
	static dissector_handle_t nrfapi_handle;

	nrfapi_handle = create_dissector_handle(dissect_5gfapi, proto_5gfapi);

	dissector_add_uint("udp.port", NR_FAPI_PORT, nrfapi_handle);

}


